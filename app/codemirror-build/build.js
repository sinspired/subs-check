const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

// 检查 entry.mjs 是否存在
const entryPath = path.join(__dirname, 'entry.mjs');
if (!fs.existsSync(entryPath)) {
  console.error('错误：未找到 entry.mjs 文件。请先创建它（见 README 或示例）。');
  process.exit(1);
}

// 构建配置
esbuild.build({
  entryPoints: [entryPath],  // 直接使用 entry.mjs 作为入口
  bundle: true,
  format: 'iife',  // 立即执行函数，适合 <script>
  globalName: 'CodeMirrorBundle',  // 全局变量
  outfile: '../static/js/libs/codemirror.bundle.js',  // 输出路径（调整为你的实际路径）
  minify: true,  // 可选：压缩（生产用）
  sourcemap: false  // 可选：生成 source map（调试用，设为 true）
}).then(() => {
  console.log('CodeMirror 打包完成: ../static/js/libs/codemirror.bundle.js');
}).catch((error) => {
  console.error('打包失败:', error);
  process.exit(1);
});