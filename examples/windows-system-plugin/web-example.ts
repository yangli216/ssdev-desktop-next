import { connectDesktop } from '@bsoft/ssdev-web-bridge'

const { bridge } = await connectDesktop()

const system = await bridge.invokePlugin('windows.system', 'getSystemInfo', {})
if (system.ResCode !== 0 || typeof system.ResData !== 'object') {
  throw new Error(`Windows system plugin failed: ${JSON.stringify(system)}`)
}

const data = system.ResData as { ReturnValue?: number; value?: string }
if (data.ReturnValue !== 0 || !data.value) {
  throw new Error(`Win32 call failed: ${JSON.stringify(data)}`)
}

console.log('native system information', JSON.parse(data.value))

// A visible native side effect. Call this only from an explicit user action.
export async function showNativeMessage() {
  return bridge.invokePlugin('windows.system', 'showMessage', {
    title: 'SSDEV Desktop',
    message: 'This window was created by the isolated native plugin host.',
  })
}
