/** Narrow read-only access to the context snapshot already projected into an agent session. */
import { defineTool } from '../../../core/tools/lib/index.js'

export const name = 'tool-load-instructions'
/** @type {['tools']} */
export const inject = ['tools']

const TOOL_NAME = 'load_instructions'
const CONTEXT_NAME = 'current_runtime_context'
const VPS_READ_TOOLS = Object.freeze(['vps_list', 'vps_find', 'vps_read', 'vps_git_status', 'vps_git_log', 'vps_search_read', 'vps_repo_summary'])
const MANAGED_TOOLS = Object.freeze([TOOL_NAME, ...VPS_READ_TOOLS])

function currentRuntimeContext(agent) {
  const nodes = agent.session.surface.nodes
  for (let index = nodes.length - 1; index >= 0; index -= 1) {
    const event = agent.session.eventAt(nodes[index])
    if (event?.type !== 'user/message' || event.data.source?.kind !== 'runtime-context') continue
    const text = event.data.content
      .filter(block => block.type === 'text' && typeof block.text === 'string')
      .map(block => block.text)
      .join('')
    return text || 'Current runtime context is empty.'
  }
  return 'Current runtime context is empty.'
}

/**
 * @param {{ tools: { register: (definition: object) => unknown }; on: (event: string, listener: (payload: object) => unknown) => unknown }} ctx
 * @returns {void}
 */
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: TOOL_NAME,
    description: 'Return the current runtime-context snapshot already available to this managed agent. The only accepted name is current_runtime_context.',
    parameters: {
      name: {
        type: 'string',
        required: true,
        const: CONTEXT_NAME,
        description: 'Must be current_runtime_context.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    execute: (args, exec) => {
      if (args.name !== CONTEXT_NAME) throw new Error(`unsupported instruction name: ${args.name}`)
      if (exec.agent === undefined) throw new Error(`${TOOL_NAME} requires a calling agent`)
      return currentRuntimeContext(exec.agent)
    },
  }))

  // The local-managed SDK profile exposes this context reader and the bounded
  // VPS readers only. The scoped guard denies any hidden or future tool schema.
  ctx.on('agent/created', ({ agent }) => {
    agent.ctx.tools.restrict({ allow: MANAGED_TOOLS })
    agent.ctx.tools.guard(exec => exec.name === TOOL_NAME
      ? undefined
      : VPS_READ_TOOLS.includes(exec.name)
        ? undefined
        : 'This managed profile permits only load_instructions and bounded vps_* read tools.')
  })
}
