'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const { evaluate, issuePayload, reportRun } = require('./watchdog-policy.cjs')

const config = { repository: 'ChrisX101010/flock', branch: 'master',
  workflowPath: '.github/workflows/regression-watchdog.yml', maxIssues: 1,
  allowedSteps: ['Phase 17 consensus finality', 'Phase 19 peer-to-peer consensus'] }
const workflow = { id: 44, path: config.workflowPath }
function run(overrides = {}) {
  return { id: 200, workflow_id: 44, path: config.workflowPath, event: 'schedule',
    head_branch: 'master', head_sha: 'a'.repeat(40), status: 'completed', conclusion: 'failure',
    head_repository: { full_name: config.repository }, created_at: '2026-11-15T02:00:00Z', ...overrides }
}
function baseline(overrides = {}) {
  return run({ id: 100, conclusion: 'success', head_sha: 'b'.repeat(40),
    created_at: '2026-11-14T02:00:00Z', ...overrides })
}
function job(attempt, gate = config.allowedSteps[0], overrides = {}) {
  return { id: attempt, run_id: 200, name: `Attempt ${attempt} / phase1`,
    status: 'completed', conclusion: 'failure', steps: [
      { name: gate, status: 'completed', conclusion: 'failure' }], ...overrides }
}
const paired = () => [job(1), job(2)]

test('reports only a repeated allowlisted gate after a green baseline', () => {
  const value = evaluate(run(), paired(), [baseline()], workflow, config)
  assert.equal(value.reason, 'confirmed-gate-failure')
  assert.equal(value.findings.length, 1)
  assert.equal(value.findings[0].gate, config.allowedSteps[0])
})

for (const [name, change] of Object.entries({
  fork: { head_repository: { full_name: 'someone/flock' } },
  branch: { head_branch: 'feature' }, pr: { event: 'pull_request' },
  spoofedWorkflow: { workflow_id: 999 }, spoofedPath: { path: '.github/workflows/other.yml' },
  cancelled: { conclusion: 'cancelled' }, running: { status: 'in_progress' },
  badSha: { head_sha: 'not-a-commit' }, badId: { id: '200;bad' },
  badDate: { created_at: 'not-a-date' }
})) {
  test(`rejects ${name} run metadata`, () => {
    assert.equal(evaluate(run(change), paired(), [baseline()], workflow, config).findings.length, 0)
  })
}
test('requires the expected workflow identity and path', () => {
  assert.equal(evaluate(run(), paired(), [baseline()], { id: 44, path: 'wrong' }, config).findings.length, 0)
})
test('ignores histories without a recent earlier matching successful run', () => {
  for (const history of [[], [baseline({ id: 201 })], [baseline({ conclusion: 'failure' })],
    [baseline({ created_at: '2026-10-01T02:00:00Z' })], [baseline({ event: 'pull_request' })],
    [baseline({ head_branch: 'feature' })], [baseline({ created_at: '2026-11-16T02:00:00Z' })]]) {
    assert.equal(evaluate(run(), paired(), history, workflow, config).findings.length, 0)
  }
})
test('requires two distinct completed attempts with the same failed gate', () => {
  for (const jobs of [[job(1)], [job(1), job(1)], [job(1), job(2, config.allowedSteps[1])],
    [job(1), job(2, undefined, { conclusion: 'success' })],
    [job(1), job(2, undefined, { status: 'in_progress' })],
    [job(1), job(2, undefined, { run_id: 999 })]]) {
    assert.equal(evaluate(run(), jobs, [baseline()], workflow, config).findings.length, 0)
  }
})
test('does not report setup, build or timeout failures', () => {
  for (const gate of ['Set up job', 'Build pinned Goose compiler', 'Install build dependencies']) {
    assert.equal(evaluate(run(), [job(1, gate), job(2, gate)], [baseline()], workflow, config).findings.length, 0)
  }
  assert.equal(evaluate(run(), [job(1), job(2, undefined, { conclusion: 'timed_out' })],
    [baseline()], workflow, config).findings.length, 0)
})
test('a different unallowlisted failed step in the same job blocks reporting', () => {
  const jobs = paired()
  jobs[0].steps.push({ name: 'Post cleanup', status: 'completed', conclusion: 'failure' })
  assert.equal(evaluate(run(), jobs, [baseline()], workflow, config).findings.length, 0)
})
test('payload contains fixed metadata and links, never job logs or arbitrary names', () => {
  const finding = evaluate(run(), paired(), [baseline()], workflow, config).findings[0]
  const payload = issuePayload(finding, run(), config)
  assert.match(payload.title, /Repeated CI failure/)
  assert.match(payload.body, /actions\/runs\/200/)
  assert.match(payload.body, /not a security classification/)
  assert.match(payload.body, /regression-watchdog:v1:/)
  assert.ok(!payload.body.includes('stderr'))
  assert.throws(() => issuePayload({ ...finding, gate: 'untrusted\n<script>' }, run(), config))
})

function harness({ runs = [baseline()], jobs = paired(), issues = [], apiError = false } = {}) {
  const created = []
  const method = name => Object.assign(() => {}, { kind: name })
  const github = { rest: {
    actions: {
      getWorkflow: async () => ({ data: workflow }),
      getWorkflowRun: async () => ({ data: run() }),
      listJobsForWorkflowRun: method('jobs'),
      listWorkflowRuns: async () => ({ data: { workflow_runs: runs } })
    },
    issues: { listForRepo: method('issues'), create: async value => {
      created.push(value); return { data: { number: 1 } }
    } }
  }, paginate: async method => {
    if (apiError) throw new Error('API unavailable')
    return method.kind === 'jobs' ? jobs : issues
  } }
  const core = { notice: () => {}, info: () => {} }
  const context = { repo: { owner: 'ChrisX101010', repo: 'flock' },
    payload: { workflow_run: { id: 200 } } }
  return { github, context, core, created }
}
test('reporter creates one issue using only API-validated evidence', async () => {
  const h = harness()
  await reportRun(h, config)
  assert.equal(h.created.length, 1)
  assert.equal(h.created[0].owner, 'ChrisX101010')
  assert.equal(h.created[0].repo, 'flock')
})
test('deduplicates both open and closed bot issues for the same green baseline', async () => {
  const finding = evaluate(run(), paired(), [baseline()], workflow, config).findings[0]
  const { marker } = issuePayload(finding, run(), config)
  for (const state of ['open', 'closed']) {
    const h = harness({ issues: [{ state, body: marker, user: { login: 'github-actions[bot]' } }] })
    await reportRun(h, config)
    assert.equal(h.created.length, 0)
  }
})
test('an untrusted user cannot suppress a report with a copied marker', async () => {
  const finding = evaluate(run(), paired(), [baseline()], workflow, config).findings[0]
  const h = harness({ issues: [{ body: issuePayload(finding, run(), config).marker,
    user: { login: 'someone' } }] })
  await reportRun(h, config)
  assert.equal(h.created.length, 1)
})
test('a zero issue budget does not publish', async () => {
  const h = harness()
  await reportRun(h, { ...config, maxIssues: 0 })
  assert.equal(h.created.length, 0)
})
test('API failures never create issues', async () => {
  const h = harness({ apiError: true })
  await assert.rejects(reportRun(h, config), /API unavailable/)
  assert.equal(h.created.length, 0)
})
test('cold start and mismatched repository context never create issues', async () => {
  const cold = harness({ runs: [] })
  await reportRun(cold, config)
  assert.equal(cold.created.length, 0)
  const wrong = harness()
  wrong.context.repo.repo = 'another'
  await assert.rejects(reportRun(wrong, config), /repository/)
  assert.equal(wrong.created.length, 0)
})
