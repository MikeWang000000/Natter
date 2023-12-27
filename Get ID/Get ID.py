import json
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.dnspod.v20210323 import dnspod_client, models

# 读取整个配置文件
with open('../config.json', 'r', encoding='utf-8') as config_file:
    all_configs = json.load(config_file)

# 单独拿出 tencent_api 的配置
tencent_api_config = all_configs.get("tencent_api", {})

# 申请域名解析 的配置
script_name_static_creation = "script0"
config_static_creation = all_configs.get(script_name_static_creation, {}) 



try:
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

    # 实例化一个请求对象,每个接口都会对应一个request对象
    req = models.DescribeRecordFilterListRequest()
    params = {
     "Domain": config_static_creation["Domain"],
    }
    req.from_json_string(json.dumps(params))

    # 返回的resp是一个DescribeRecordFilterListResponse的实例，与请求对象对应
    resp = client.DescribeRecordFilterList(req)

    # 提取指定字段并按照指定顺序输出到控制台
    record_list = resp.RecordList
    max_len_name = max(len(record.Name) for record in record_list)  # 计算主机记录字段的最大长度
    max_len_id = max(len(str(record.RecordId)) for record in record_list)  # 计算ID字段的最大长度
    max_len_value = max(len(str(record.Value)) for record in record_list)  # 计算IP字段的最大长度

    # 将日志信息写入 JSON 文件
    log_data = {
        "RecordList": [
            {
                "Name": record.Name,
                "RecordId": record.RecordId,
                "Value": record.Value
            } for record in record_list
        ]
    }

    with open('record.json', 'w', encoding='utf-8') as log_file:
        json.dump(log_data, log_file, ensure_ascii=False, indent=2)

    for record in record_list:
        output_data = {
            "主机记录": record.Name.ljust(max_len_name),
            "ID": str(record.RecordId).ljust(max_len_id),
            "IP": str(record.Value).ljust(max_len_value)
        }
        # 在逗号后面添加额外的空位
        print("主机记录: {主机记录} , ID: {ID}, IP: {IP}".format(**output_data))

except TencentCloudSDKException as err:
    print(err)
