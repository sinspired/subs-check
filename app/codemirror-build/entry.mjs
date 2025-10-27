// entry.mjs - CodeMirror 6 ESM 入口（修复 EditorState 导入）
import { EditorView, basicSetup } from 'codemirror';  // 核心（EditorView + basicSetup）
import { EditorState } from '@codemirror/state';     // EditorState 单独导入
import { yaml } from '@codemirror/lang-yaml';
import { oneDark } from '@codemirror/theme-one-dark';
import { keymap } from "@codemirror/view";
import { indentWithTab } from "@codemirror/commands";
import { autocompletion } from "@codemirror/autocomplete";
import { CompletionContext } from "@codemirror/autocomplete";

// 配置键的自动完成列表（基于提供的 YAML 模板提取）
const configCompletions = [
  { label: "print-progress", type: "property" },
  { label: "progress-mode", type: "property" },
  { label: "update", type: "property" },
  { label: "update-on-startup", type: "property" },
  { label: "cron-check-update", type: "property" },
  { label: "prerelease", type: "property" },
  { label: "update-timeout", type: "property" },
  { label: "concurrent", type: "property" },
  { label: "alive-concurrent", type: "property" },
  { label: "speed-concurrent", type: "property" },
  { label: "media-concurrent", type: "property" },
  { label: "check-interval", type: "property" },
  { label: "cron-expression", type: "property" },
  { label: "success-limit", type: "property" },
  { label: "timeout", type: "property" },
  { label: "speed-test-url", type: "property" },
  { label: "min-speed", type: "property" },
  { label: "download-timeout", type: "property" },
  { label: "download-mb", type: "property" },
  { label: "total-speed-limit", type: "property" },
  { label: "threshold", type: "property" },
  { label: "listen-port", type: "property" },
  { label: "rename-node", type: "property" },
  { label: "node-prefix", type: "property" },
  { label: "node-type", type: "property" },
  { label: "media-check", type: "property" },
  { label: "platforms", type: "property" },
  { label: "drop-bad-cf-nodes", type: "property" },
  { label: "enhanced-tag", type: "property" },
  { label: "maxmind-db-path", type: "property" },
  { label: "output-dir", type: "property" },
  { label: "keep-success-proxies", type: "property" },
  { label: "enable-web-ui", type: "property" },
  { label: "api-key", type: "property" },
  { label: "callback-script", type: "property" },
  { label: "apprise-api-server", type: "property" },
  { label: "recipient-url", type: "property" },
  { label: "notify-title", type: "property" },
  { label: "sub-store-port", type: "property" },
  { label: "sub-store-path", type: "property" },
  { label: "mihomo-overwrite-url", type: "property" },
  { label: "singbox-latest", type: "property" },
  { label: "singbox-old", type: "property" },
  { label: "sub-store-sync-cron", type: "property" },
  { label: "sub-store-produce-cron", type: "property" },
  { label: "sub-store-push-service", type: "property" },
  { label: "save-method", type: "property" },
  { label: "webdav-url", type: "property" },
  { label: "webdav-username", type: "property" },
  { label: "webdav-password", type: "property" },
  { label: "github-gist-id", type: "property" },
  { label: "github-token", type: "property" },
  { label: "github-api-mirror", type: "property" },
  { label: "worker-url", type: "property" },
  { label: "worker-token", type: "property" },
  { label: "s3-endpoint", type: "property" },
  { label: "s3-access-id", type: "property" },
  { label: "s3-secret-key", type: "property" },
  { label: "s3-bucket", type: "property" },
  { label: "s3-use-ssl", type: "property" },
  { label: "s3-bucket-lookup", type: "property" },
  { label: "system-proxy", type: "property" },
  { label: "github-proxy", type: "property" },
  { label: "ghproxy-group", type: "property" },
  { label: "sub-urls-retry", type: "property" },
  { label: "success-rate", type: "property" },
  { label: "sub-urls-remote", type: "property" },
  { label: "sub-urls", type: "property" },
];

// YAML 配置键自动完成源
const yamlConfigSource = (context) => {
  const word = context.matchBefore(/[\w-]*$/);
  if (word?.from === word?.to && !context.explicit) {
    return null;
  }
  return {
    from: word.from,
    options: configCompletions
      .filter((option) => option.label.startsWith(word.text))
      .map((option) => ({
        ...option,
        apply: `${option.label}: `,  // 自动插入键名后跟冒号和空格
      })),
  };
};

// 全局暴露
window.CodeMirror = {
  createEditor: (container, initialValue = '', theme = 'light') => {
    if (!container || !(container instanceof HTMLElement)) {
      throw new Error('Invalid parent: must be a valid HTMLElement (e.g., <div>)');
    }

    const extensions = [
      basicSetup,  // 基础（默认行号、折叠等）
      yaml(),      // YAML 高亮
      EditorView.lineWrapping,  // 启用基本软换行（视口宽度自动折叠）
      keymap.of([indentWithTab]),
      autocompletion({ override: [yamlConfigSource] }),  // 自动完成扩展
      theme === 'dark' ? oneDark : null  // 主题
    ].filter(Boolean);  // 过滤 null/undefined，避免扩展错误

    const state = EditorState.create({
      doc: initialValue,
      extensions
    });

    return new EditorView({
      state,
      parent: container
    });
  },
  getValue: (view) => view.state.doc.toString(),
  setValue: (view, value) => view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } }),
  focus: (view) => view.focus(),
  destroy: (view) => view.destroy()  // 用于清理
};