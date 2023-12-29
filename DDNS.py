# 导入所需的模块
import json  # 导入处理 JSON 数据的模块
import logging  # 导入日志记录模块
import time  # 导入时间模块
from tencentcloud.common import credential  
from tencentcloud.common.profile.client_profile import ClientProfile  
from tencentcloud.common.profile.http_profile import HttpProfile  
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException 
from tencentcloud.dnspod.v20210323 import dnspod_client, models  


# 设置日志级别为 INFO，修改 format 和 datefmt 参数
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H')

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



# 读取缓存文件中的动态IP信息


def get_current_ip():
    try:
        with open("Cache.json", "r", encoding="utf-8") as cache_file:
            cache_data = json.load(cache_file)
            current_ip = cache_data.get("mapped_external_ip", None)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        current_ip = None
    return current_ip
 



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
last_PORT = None

# 初始化 IP 变量
last_IP = None



try:
    while True:
            # 获取动态端口
        PORT = read_dynamic_port()

        if PORT != last_PORT:    #对比



            last_PORT = PORT     #有变化就写进去

            try:
                        # 修改 DDNS 记录
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
                log_message = f"您的域名 {config_dynamic_port['domain']} 更新成功, 当前端口号 {PORT}"
                logging.info(log_message)


            except TencentCloudSDKException as err:
                log_error = f"Tencent Cloud SDK 异常：{err}"
                logging.error(log_error)

        else:
                log_message = "当前 PORT 与之前保存的 PORT 相同，无需更新"
                logging.info(log_message)

        # 获取当前公网 IP
        IP = get_current_ip()

        if IP != last_IP:

   
                last_IP = IP


                # 修改 DDNS 记录
                update_req = models.ModifyRecordRequest()
                update_params = {
                    "Domain": config_static_ip["domain"],
                    "SubDomain": config_static_ip["SubDomain"],
                    "RecordType": config_static_ip["RecordType"],
                    "RecordId": config_static_ip["record_id"],
                    "RecordLine": config_static_ip["RecordLine"],
                    "Value": IP
                }
                update_req.from_json_string(json.dumps(update_params))
                update_resp = client.ModifyRecord(update_req)
                log_message = f"您的域名 {config_static_ip['domain']} DDNS 已更新。新IP: {IP}"
                logging.info(log_message)

            
        else:
                    log_message = "当前公网 IP 与之前保存的 IP 相同，无需更新"
                    logging.info(log_message)

        # 等待一段时间之后继续检查
        time.sleep(config_static_ip["sleep"])


except Exception as e:
        log_error = f"发生严重错误：{e}"
        logging.exception(log_error)