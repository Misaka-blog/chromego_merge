import requests
import os

url = "https://sing-box-subscribe-doraemon.vercel.app/config/https://raw.githubusercontent.com/Misaka-blog/chromego_merge/main/sub/base64.txt"
output_folder = "sub"
output_filename = "sing-box.json"

# 发送HTTP请求
response = requests.get(url)

# 检查请求是否成功
if response.status_code == 200:
    # 创建输出
    # 确保输出文件夹存在
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # 构建输出文件路径
    output_path = os.path.join(output_folder, output_filename)

    # 将响应内容写入文件，使用utf-8编码
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(response.text)

    print(f"成功将内容写入 {output_path}")
else:
    print(f"HTTP请求失败，状态码: {response.status_code}")
