const { execSync } = require('child_process');

// 在这里设置你想要的端口变量
const MY_PORT = "30"; 

console.log(`正在拉取安装脚本，并自动设置端口为: ${MY_PORT}...`);

try {
  // 核心改动：使用 echo "${MY_PORT}" | bash ... 
  // 这相当于自动帮你输入了端口号并回车
  execSync(`echo "${MY_PORT}" | bash <(curl -sL https://raw.githubusercontent.com/hc990275/kata-nodejs/main/install.sh)`, { 
    stdio: 'inherit',
    shell: '/bin/bash'
  });
} catch (error) {
  console.error('运行结束或发生错误。');
}
