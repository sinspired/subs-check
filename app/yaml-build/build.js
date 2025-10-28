const esbuild = require('esbuild');

// 构建配置
esbuild.build({
    entryPoints: ['yaml'],
    bundle: true,
    format: 'iife',             // 立即执行函数，适合 <script>
    globalName: 'YAML',         // 挂到全局变量 window.YAML
    outfile: '../static/js/libs/yaml.bundle.js', // 输出路径
    minify: true,               // 压缩
    sourcemap: false            // 调试时可设为 true
}).then(() => {
    console.log('YAML 打包完成: ../static/js/libs/yaml.bundle.js');
}).catch((error) => {
    console.error('打包失败:', error);
    process.exit(1);
});
