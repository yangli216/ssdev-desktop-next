import { invoke } from '@tauri-apps/api/core'
import './capture.css'

type Point = { x: number; y: number }
type Selection = { left: number; top: number; width: number; height: number }

const root = document.querySelector<HTMLElement>('#capture')!
const snapshot = document.querySelector<HTMLImageElement>('#snapshot')!
const selectionBox = document.querySelector<HTMLElement>('#selection')!
const actions = document.querySelector<HTMLElement>('#actions')!
const confirm = document.querySelector<HTMLButtonElement>('#confirm')!
const cancel = document.querySelector<HTMLButtonElement>('#cancel')!
const error = document.querySelector<HTMLElement>('#error')!

let start: Point | null = null
let selection: Selection | null = null
let activePointer: number | null = null

function clamp(value: number, maximum: number) {
  return Math.max(0, Math.min(value, maximum))
}

function point(event: PointerEvent): Point {
  return {
    x: clamp(event.clientX, window.innerWidth),
    y: clamp(event.clientY, window.innerHeight),
  }
}

function selectionFrom(a: Point, b: Point): Selection {
  const left = Math.min(a.x, b.x)
  const top = Math.min(a.y, b.y)
  return {
    left,
    top,
    width: Math.abs(a.x - b.x),
    height: Math.abs(a.y - b.y),
  }
}

function render(current: Selection) {
  selectionBox.hidden = false
  selectionBox.style.left = `${current.left}px`
  selectionBox.style.top = `${current.top}px`
  selectionBox.style.width = `${current.width}px`
  selectionBox.style.height = `${current.height}px`
}

root.addEventListener('pointerdown', (event) => {
  if ((event.target as HTMLElement).closest('#actions')) return
  activePointer = event.pointerId
  root.setPointerCapture(event.pointerId)
  start = point(event)
  selection = { left: start.x, top: start.y, width: 0, height: 0 }
  actions.hidden = true
  render(selection)
})

root.addEventListener('pointermove', (event) => {
  if (activePointer !== event.pointerId || !start) return
  selection = selectionFrom(start, point(event))
  render(selection)
})

root.addEventListener('pointerup', (event) => {
  if (activePointer !== event.pointerId || !start) return
  selection = selectionFrom(start, point(event))
  activePointer = null
  start = null
  if (selection.width < 4 || selection.height < 4) {
    selection = null
    selectionBox.hidden = true
    actions.hidden = true
    return
  }
  render(selection)
  actions.hidden = false
})

async function cancelCapture() {
  await invoke('cancel_region_capture')
}

confirm.addEventListener('click', async () => {
  if (!selection) return
  confirm.disabled = true
  cancel.disabled = true
  try {
    await invoke('complete_region_capture', {
      selection: {
        left: selection.left / window.innerWidth,
        top: selection.top / window.innerHeight,
        width: selection.width / window.innerWidth,
        height: selection.height / window.innerHeight,
      },
    })
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : String(reason)
    error.hidden = false
    confirm.disabled = false
    cancel.disabled = false
  }
})

cancel.addEventListener('click', () => void cancelCapture())
window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') void cancelCapture()
})
window.addEventListener('contextmenu', (event) => {
  event.preventDefault()
  void cancelCapture()
})

try {
  snapshot.src = await invoke<string>('capture_region_snapshot')
  await snapshot.decode()
  root.dataset.ready = 'true'
} catch (reason) {
  error.textContent = reason instanceof Error ? reason.message : String(reason)
  error.hidden = false
}
