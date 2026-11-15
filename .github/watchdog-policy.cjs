'use strict'

const { createHash } = require('node:crypto')

function matchesRun(run, workflow, config) {
  return Boolean(run && workflow && workflow.path === config.workflowPath &&
    Number.isSafeInteger(workflow.id) && Number.isSafeInteger(run.id) && run.id > 0 &&
    run.workflow_id === workflow.id && run.path === config.workflowPath &&
    ['schedule', 'workflow_dispatch'].includes(run.event) &&
    run.head_branch === config.branch && run.head_repository?.full_name === config.repository &&
    /^[a-f0-9]{40}$/.test(run.head_sha || '') && run.status === 'completed' &&
    Number.isFinite(Date.parse(run.created_at)))
}

function evaluate(run, jobs, history, workflow, config) {
  const none = reason => ({ reason, findings: [] })
  if (!matchesRun(run, workflow, config) || run.conclusion !== 'failure') {
    return none('ineligible-run')
  }
  const currentTime = Date.parse(run.created_at)
  const baseline = history.filter(previous => {
    const age = currentTime - Date.parse(previous.created_at)
    return matchesRun(previous, workflow, config) && previous.conclusion === 'success' &&
      previous.id < run.id && age > 0 && age <= 14 * 24 * 60 * 60 * 1000
  }).sort((a, b) => b.id - a.id)[0]
  if (!baseline) return none('no-recent-green-baseline')
  if (!Array.isArray(jobs) || !jobs.length || new Set(jobs.map(j => j.id)).size !== jobs.length ||
      jobs.some(j => !Number.isSafeInteger(j.id) || j.id <= 0 || j.run_id !== run.id)) {
    return none('invalid-job-metadata')
  }
  const gates = [new Set(), new Set()]
  const seen = [false, false]
  const blocked = [false, false]
  for (const job of jobs) {
    const attempt = /^Attempt ([12]) \/ /.exec(job.name || '')
    if (!attempt) continue
    const index = Number(attempt[1]) - 1
    seen[index] = true
    if (job.status !== 'completed' || !['success', 'failure', 'skipped'].includes(job.conclusion)) {
      blocked[index] = true
      continue
    }
    if (job.conclusion !== 'failure') continue
    const failed = (job.steps || []).filter(step => step.conclusion === 'failure')
    if (!failed.length || failed.some(step => step.status !== 'completed' ||
        !config.allowedSteps.includes(step.name))) {
      blocked[index] = true
      continue
    }
    for (const step of failed) gates[index].add(step.name)
  }
  if (seen.some(value => !value) || blocked.some(Boolean)) return none('unconfirmed-attempts')
  const findings = [...gates[0]].filter(gate => gates[1].has(gate)).sort()
    .map(gate => ({ gate, baselineId: baseline.id, baselineSha: baseline.head_sha }))
  return findings.length ? { reason: 'confirmed-gate-failure', findings } : none('no-matching-gate-failure')
}

function issuePayload(finding, run, config) {
  if (!config.allowedSteps.includes(finding.gate) || !Number.isSafeInteger(finding.baselineId) ||
      !Number.isSafeInteger(run.id) || !/^[a-f0-9]{40}$/.test(run.head_sha || '') ||
      !/^[a-f0-9]{40}$/.test(finding.baselineSha || '')) throw new Error('Invalid issue evidence')
  const fingerprint = createHash('sha256').update(finding.gate).digest('hex').slice(0, 24)
  const marker = `<!-- regression-watchdog:v1:${fingerprint}:${finding.baselineId} -->`
  const baseUrl = `https://github.com/${config.repository}`
  return {
    marker,
    title: `Repeated CI failure: ${finding.gate}`,
    body: `${marker}\n\nThe allowlisted gate **${finding.gate}** failed in both clean CI attempts ` +
      `against commit [${run.head_sha.slice(0, 12)}](${baseUrl}/commit/${run.head_sha}).\n\n` +
      `- Failed run: ${baseUrl}/actions/runs/${run.id}\n` +
      `- Last successful watchdog baseline: ${baseUrl}/actions/runs/${finding.baselineId}\n` +
      `- Baseline commit: ${finding.baselineSha}\n\n` +
      `This confirms a repeated gate failure, not its root cause. It is not a security classification. ` +
      `A maintainer should distinguish a code regression from dependency or runner changes. ` +
      `Suspected security defects should be triaged privately. No test inputs or raw logs are copied here.\n\n` +
      `The watchdog opens at most one issue per run and suppresses this gate until a new green baseline.`
  }
}

async function reportRun({ github, context, core }, config) {
  const repository = `${context.repo.owner}/${context.repo.repo}`
  if (repository !== config.repository) throw new Error('Unexpected repository context')
  if (!Number.isInteger(config.maxIssues) || config.maxIssues < 0 || config.maxIssues > 1) {
    throw new Error('Issue budget must be zero or one')
  }
  const id = context.payload.workflow_run?.id
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error('Invalid workflow run ID')
  const ownerRepo = { owner: context.repo.owner, repo: context.repo.repo }
  const workflow = (await github.rest.actions.getWorkflow({ ...ownerRepo,
    workflow_id: config.workflowPath.split('/').pop() })).data
  const run = (await github.rest.actions.getWorkflowRun({ ...ownerRepo, run_id: id })).data
  if (!matchesRun(run, workflow, config) || run.id !== id || run.conclusion !== 'failure') {
    core.notice('No eligible failed default-branch watchdog run.')
    return
  }
  const history = (await github.rest.actions.listWorkflowRuns({ ...ownerRepo,
    workflow_id: workflow.id, branch: config.branch, status: 'success', per_page: 100 })).data.workflow_runs
  const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun,
    { ...ownerRepo, run_id: id, filter: 'latest', per_page: 100 })
  const result = evaluate(run, jobs, history, workflow, config)
  core.notice(result.reason)
  if (!result.findings.length || config.maxIssues === 0) return
  // Read open AND closed issues: closing a report must not cause daily reposts.
  const issues = await github.paginate(github.rest.issues.listForRepo,
    { ...ownerRepo, state: 'all', per_page: 100 })
  let created = 0
  for (const finding of result.findings) {
    if (created >= config.maxIssues) break
    const payload = issuePayload(finding, run, config)
    const exists = issues.some(issue => !issue.pull_request &&
      issue.user?.login === 'github-actions[bot]' && (issue.body || '').includes(payload.marker))
    if (exists) {
      core.info('Existing report for this gate and baseline; no duplicate created.')
      continue
    }
    await github.rest.issues.create({ ...ownerRepo, title: payload.title, body: payload.body })
    created++
  }
}

// EXPORTS: excluded from the embedded, checkout-free reporter.
module.exports = { evaluate, issuePayload, reportRun }
