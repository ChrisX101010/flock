'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { createHash } = require('node:crypto')
const read = name => fs.readFileSync(path.join(__dirname, name), 'utf8')
const reporter = read('workflows/regression-report.yml')
const watchdog = read('workflows/regression-watchdog.yml')
const policy = read('watchdog-policy.cjs').split('// EXPORTS:')[0].trimEnd()
const embedded = reporter.split('          script: |\n')[1].trimEnd()
  .split('\n').map(line => {
    if (!line) return ''
    assert.ok(line.startsWith('            ')); return line.slice(12)
  }).join('\n')
const config = JSON.parse(embedded.match(/\nconst config = ([\s\S]+?);\nawait reportRun/)[1])
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor

test('privileged workflow embeds the exact tested policy and executes no repository/artifact code', () => {
  assert.ok(embedded.startsWith(policy + '\n\nconst config = '))
  assert.ok(!reporter.includes('actions/checkout'))
  assert.ok(!reporter.includes('download-artifact'))
  assert.ok(!reporter.includes('pull_request_target'))
  assert.ok(!embedded.includes('${{'))
  assert.match(reporter, /actions\/github-script@[a-f0-9]{40}/)
  assert.match(watchdog, /permissions:\n  contents: read\n/)
  assert.ok(!watchdog.includes('issues: write'))
  assert.ok(!watchdog.includes('secrets: inherit'))
  assert.match(watchdog, /pull_request:/)
  assert.match(watchdog, /name: Attempt 2\n    needs: attempt_1\n    if: \$\{\{ !cancelled\(\) \}\}/)
})

function fixture(event = 'schedule', repo = config.repository) {
  const [owner, name] = config.repository.split('/')
  const workflow = { id: 44, path: config.workflowPath }
  const run = { id: 200, workflow_id: 44, path: config.workflowPath,
    event, head_branch: 'master', head_sha: 'a'.repeat(40),
    status: 'completed', conclusion: 'failure', head_repository: { full_name: repo },
    created_at: '2026-11-15T02:00:00Z' }
  const baseline = { ...run, id: 100, conclusion: 'success', head_sha: 'b'.repeat(40),
    created_at: '2026-11-14T02:00:00Z' }
  const jobs = [1, 2].map(n => ({ id: n, run_id: 200, name: `Attempt ${n} / example`,
    status: 'completed', conclusion: 'failure', steps: [
      { name: config.allowedSteps[0], status: 'completed', conclusion: 'failure' }] }))
  const calls = []
  const tagged = kind => Object.assign(() => {}, { kind })
  return {
    calls,
    context: { repo: { owner, repo: name }, payload: { workflow_run: { id: 200 } } },
    core: { notice() {}, info() {} },
    github: { rest: {
      actions: {
        getWorkflow: async () => ({ data: workflow }),
        getWorkflowRun: async () => ({ data: run }),
        listWorkflowRuns: async () => ({ data: { workflow_runs: [baseline] } }),
        listJobsForWorkflowRun: tagged('jobs')
      },
      issues: { listForRepo: tagged('issues'), create: async payload => {
        calls.push(payload); return { data: { number: 1 } }
      } }
    }, paginate: async method => method.kind === 'jobs' ? jobs : [] }
  }
}

test('actual embedded reporter creates one metadata-only issue for valid paired failures', async () => {
  const h = fixture()
  await new AsyncFunction('github', 'context', 'core', 'require', embedded)(
    h.github, h.context, h.core, require)
  assert.equal(h.calls.length, 1)
  assert.equal(h.calls[0].owner + '/' + h.calls[0].repo, config.repository)
  assert.match(h.calls[0].body, /actions\/runs\/200/)
})

test('actual embedded reporter ignores PR events and foreign source repositories', async () => {
  for (const h of [fixture('pull_request'), fixture('workflow_dispatch', 'other/project')]) {
    await new AsyncFunction('github', 'context', 'core', 'require', embedded)(
      h.github, h.context, h.core, require)
    assert.equal(h.calls.length, 0)
  }
})

test('every configured public gate exists in the reusable CI source', () => {
  const ci = read('workflows/ci.yml')
  for (const gate of config.allowedSteps) assert.ok(ci.includes(`- name: ${gate}\n`), gate)
  assert.ok(config.allowedSteps.length > 0)
  assert.equal(config.maxIssues, 1)
  assert.equal(config.branch, 'master')
  assert.match(ci, /workflow_call:/)
  assert.match(ci, /timeout-minutes: 30/)
  assert.equal(createHash('sha256').update(policy).digest('hex').length, 64)
})
