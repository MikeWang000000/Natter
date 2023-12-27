# 导入所需的模块
import json  # 导入处理 JSON 数据的模块
import requests  # 导入用于发送HTTP请求的模块
import re  # 导入正则表达式模块
import logging  # 导入日志记录模块
import time  # 导入时间模块
from tencentcloud.common import credential  
from tencentcloud.common.profile.client_profile import ClientProfile  
from tencentcloud.common.profile.http_profile import HttpProfile  
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException 
from tencentcloud.dnspod.v20210323 import dnspod_client, models  


# 设置日志级别为 INFO，修改 format 和 datefmt 参数
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M')

# 读取整个配置文件
with open('config.json', 'r', encoding='utf-8') as config_file:
    all_configs = json.load(config_file)  

# 获取动态端口的配置
script_name_dynamic_port = "script2"
config_dynamic_port = all_configs.get(script_name_dynamic_port, {})  

# 获取公网 IP 的配置
script_name_static_ip = "script1"
config_static_ip = all_configs.get(script_name_static_ip, {}) 

# 单独拿出 tencent_api 的配置
tencent_api_config = all_configs.get("tencent_api", {})  

# 读取缓存文件中的动态端口信息
def read_dynamic_port():
    try:
        with open("Cache.json", "r", encoding="utf-8") as cache_file:
            cache_data = json.load(cache_file) 
            dynamic_port = cache_data.get("mapped_external_port", None)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        dynamic_port = None
    return dynamic_port 



# 获取公网 IP 地址
# 这里使用的是api中返回的ip地址，你也可以不用api。直接从Cache.json里的mapped_external_ip中获取

def get_current_ip():
    try:
        resp = requests.get(config_static_ip["ip_check_url"]).content  
        resp = resp.decode('utf8')
        match_obj = re.search(config_static_ip["ip_pattern"], resp)  
        return match_obj.group() if match_obj else None  
    except Exception as e:
        error_msg = str(e)
        logging.error(f"获取当前 IP 地址时发生错误：{error_msg}")
        return None
 



# 实例化要请求产品的 client 对象
cred = credential.Credential(tencent_api_config.get("secret_id", ""), tencent_api_config.get("secret_key", ""))
# 实例化一个http选项，可选的，没有特殊需求可以跳过
http_profile = HttpProfile()
http_profile.endpoint = tencent_api_config.get("endpoint", "")
# 实例化一个client选项，可选的，没有特殊需求可以跳过
client_profile = ClientProfile()
client_profile.httpProfile = http_profile
# 实例化要请求产品的client对象,clientProfile是可选的
client = dnspod_client.DnspodClient(cred, "", client_profile)



# 初始化动态端口变量
last_dynamic_port = None

# 初始化 IP 变量
ddns_ip = None



try:
    while True:
        # 获取动态端口
        dynamic_port = read_dynamic_port()

        if dynamic_port != last_dynamic_port:
            # 如果获取到动态端口则使用该值，否则使用默认端口号 14382
            PORT = dynamic_port or 14382

            last_dynamic_port = dynamic_port

            try:
                # 构造修改 DDNS 记录请求
                req = models.ModifyRecordRequest()
                params = {
                    "Domain": config_dynamic_port["domain"],
                    "SubDomain": config_dynamic_port["SubDomain"],
                    "RecordType": config_dynamic_port["RecordType"],
                    "RecordId": config_dynamic_port["record_id"],
                    "RecordLine": config_dynamic_port["RecordLine"],
                    "Value": f"{config_dynamic_port['priority']} {PORT} {config_dynamic_port['domain']}"
                }
                req.from_json_string(json.dumps(params))
                resp = client.ModifyRecord(req)

                # 打印更新成功消息和当前端口号
                logging.info(f"您的域名 {config_dynamic_port['domain']} 更新成功, 当前端口号 {PORT}")

            except TencentCloudSDKException as err:
                logging.error(f"Tencent Cloud SDK 异常：{err}")

        else:
            logging.info("端口号没有变化，无需更新")

        # 获取当前公网 IP
        current_ip = get_current_ip()

        if current_ip != ddns_ip:
            # 获取当前 DDNS 记录值
            req = models.DescribeRecordRequest()
            params = {
                "Domain": config_static_ip["domain"],
                "RecordId": config_static_ip["record_id"]
            }
            req.from_json_string(json.dumps(params))
            resp = client.DescribeRecord(req)
            ddns_ip = resp.RecordInfo.Value

            if current_ip != ddns_ip:
                logging.info("执行更新 DDNS 记录操作")

                # 修改 DDNS 记录
                update_req = models.ModifyRecordRequest()
                update_params = {
                    "Domain": config_static_ip["domain"],
                    "SubDomain": config_static_ip["SubDomain"],
                    "RecordType": config_static_ip["RecordType"],
                    "RecordId": config_static_ip["record_id"],
                    "RecordLine": config_static_ip["RecordLine"],
                    "Value": current_ip
                }
                update_req.from_json_string(json.dumps(update_params))
                update_resp = client.ModifyRecord(update_req)
                logging.info(f"您的域名 {config_static_ip['domain']} DDNS 已更新。新IP: {current_ip}")

                ddns_ip = current_ip  
            else:
                # 不要问为什么有两个输出，问就是不知道怎么写，只会if嵌套。如果你知道怎么写，那么可以改掉。
                logging.info(f"当前公网 IP 与之前保存的 DDNS IP 相同，无需更新")
        else:
            logging.info(f"当前公网 IP 与之前保存的 DDNS IP 相同，无需更新")

        # 等待一段时间之后继续检查
        time.sleep(config_static_ip["sleep"])


except Exception as e:
    logging.exception(f"发生严重错误：{e}")