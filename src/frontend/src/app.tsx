import { createSignal, onMount } from 'solid-js'

import Convert from 'ansi-to-html'
import Editor from './editor'
import Worker from './worker?worker'
import type { WorkerResponse, RunCode, CodeFile, Versions } from './types'
import { initiateOAuth2Flow, handleOAuth2Callback, isOAuthCallback } from './oauth'

const decoder = new TextDecoder()
const ansiConverter = new Convert({ colors: { 1: '#CE9178', 4: '#569CFF', 5: '#F00' } })

export default function () {
  const [status, setStatus] = createSignal<string | null>(null)
  const [running, setRunning] = createSignal(false)
  const [installed, setInstalled] = createSignal('')
  const [outputHtml, setOutputHtml] = createSignal('')
  const [versions, setVersions] = createSignal<Versions | null>(null)
  const [accessToken, setAccessToken] = createSignal<string | null>(null)
  let terminalOutput = ''
  let worker: Worker
  let outputRef!: HTMLPreElement

  onMount(async () => {
    // Handle OAuth callback if we're returning from authorization
    if (isOAuthCallback()) {
      const token = await handleOAuth2Callback()
      if (token) {
        setAccessToken(token)
      } else {
        setStatus('Failed to obtain access token')
      }
    } else if (!accessToken()) {
      // If we don't have a token and we're not in the callback, start the OAuth flow
      initiateOAuth2Flow()
    }

    worker = new Worker()
    worker.onmessage = ({ data }: { data: WorkerResponse }) => {
      let newTerminalOutput = false
      if (data.kind == 'print') {
        newTerminalOutput = true
        for (const chunk of data.data) {
          terminalOutput += decoder.decode(chunk)
        }
      } else if (data.kind == 'status') {
        setStatus(data.message)
      } else if (data.kind == 'error') {
        newTerminalOutput = true
        terminalOutput += data.message
      } else if (data.kind == 'installed') {
        setInstalled(data.message.length > 0 ? `Installed dependencies: ${data.message}` : '')
      } else if (data.kind == 'end') {
        setRunning(false)
      } else {
        setVersions(data as Versions)
      }

      if (newTerminalOutput) {
        // escape HTML codes in the terminal output
        const escapedOutput = escapeHTML(terminalOutput)
        // replace ansi links with html links since ansi-to-html doesn't support this properly
        let terminalHtml = replaceAnsiLinks(escapedOutput)
        // convert other ansi codes to html
        terminalHtml = ansiConverter.toHtml(terminalHtml)
        // set the output
        setOutputHtml(terminalHtml)
        // scrolls to the bottom of the div
        outputRef.scrollTop = outputRef.scrollHeight
      }
    }
  })

  async function runCode(files: CodeFile[]) {
    if (!accessToken()) {
      setStatus('Please authenticate first')
      return
    }

    setRunning(true)
    setStatus('Starting Python...')
    setInstalled('')
    setOutputHtml('')
    terminalOutput = ''
    worker!.postMessage({ 
      files,
      sweatstack_api_key: accessToken()
    } as RunCode)
  }

  // noinspection JSUnusedAssignment
  return (
    <main>
      <header>
        <h1>sweatstack.run</h1>
        <aside>
          Python browser sandbox, inspired by and based on{' '}
          <a href="https://pydantic.run" target="_blank">
            pydantic.run
          </a>
          . <a href="/blank">reset sandbox</a>.
        </aside>
      </header>
      <section>
        <Editor runCode={runCode} running={running()} />
        <div class="col">
          <div class="status my-5">{status() || <>&nbsp;</>}</div>
          <div class="installed">{installed()}</div>
          <pre class="output" innerHTML={outputHtml()} ref={outputRef}></pre>
          <Versions versions={versions()} />
        </div>
      </section>
    </main>
  )
}

const escapeEl = document.createElement('textarea')
function escapeHTML(html: string): string {
  escapeEl.textContent = html
  return escapeEl.innerHTML
}

// hellish regex to replace ansi links with html links since ansi-to-html doesn't know how
// warning this may be very bittle! it's written to work for the logfire project URL currently printed
// by the logfire SDK
function replaceAnsiLinks(terminalOutput: string): string {
  return terminalOutput.replace(
    // eslint-disable-next-line no-control-regex
    /\x1B]8;id=\d+;(.+?)\x1B\\(?:\x1B\[\d+;\d+m)?(.+?)(?:\x1B\[0m)?\x1B]8;;\x1B\\/g,
    (_, url, text) => `<a href="${url}" target="_blank">${text}</a>`,
  )
}

function Versions(props: { versions: Versions | null }) {
  return (
    <div class="status text-right smaller">
      {props.versions && (
        <>
          <a
            href={`https://www.python.org/downloads/release/python-${props.versions.python.replace(/\./g, '')}/`}
            target="_blank"
          >
            Python {props.versions.python}
          </a>
          ,{' '}
          <a
            href={`https://pyodide.org/en/stable/project/changelog.html#version-${props.versions.pyodide.replace(/\./g, '-')}`}
            target="_blank"
          >
            Pyodide {props.versions.pyodide}
          </a>
        </>
      )}
    </div>
  )
}
