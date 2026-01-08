// 这是一个引导安装脚本
// 作用：启动时自动下载并运行 install.sh
const { execSync } = require('child_process');

console.log('正在拉取安装脚本...');

try {
  // 修改处：添加了 shell: '/bin/bash' 选项
  execSync('bash <(curl -sL https://raw.githubusercontent.com/hc990275/kata-nodejs/main/install.sh)', { 
    stdio: 'inherit', 
    shell: '/bin/bash' 
  });
} catch (error) {
  console.error('安装过程中发生错误，或脚本已重启进程。');
}
