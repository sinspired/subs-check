// entry.mjs - CodeMirror 6 ESM 入口（修复 EditorState 导入）
import { EditorView, basicSetup } from 'codemirror';  // 核心（EditorView + basicSetup）
import { EditorState } from '@codemirror/state';     // EditorState 单独导入
import { yaml } from '@codemirror/lang-yaml';
import { oneDark } from '@codemirror/theme-one-dark';

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