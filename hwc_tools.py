# 用于 控制部署在 华为云 的服务器实例

"""
用法：
- list 列出所有运行的 ECS 实例
- expand  扩容 ECS 实例，参数为实例 ID, 如未给出且当前仅一个 ECS ，则直接使用该 ECS
- shrink  缩容 ECS 实例，参数为实例 ID
- restart 重置 ECS 实例，并远程启动对应的服务
    应该检查服务是否已经启动，然后决定是否重启。但是需要额外的记录服务运行状态等

访问 华为云的 API 需要 iAM 的 UserID 和 Password, 其中 UserID 在代码中写死，Password 通过环境变量传入
直接使用 request 库访问 API，不使用 SDK。因为 华为云的 Python SDK 年久失修。
"""
import os
import time

import argparse
import requests
from fabric import Connection

# 定义 API 访问的 ENDPOINT , 参考 https://support.huaweicloud.com/api-iam/iam_01_0004.html
EndPoint = "cn-east-3.myhuaweicloud.com"  # 华为云 上海-1 区域
# https://ecs.cn-east-3.myhuaweicloud.com/v1/{project_id}/cloudservers/detail       ECS
# iam.cn-east-3.myhuaweicloud.com

# 写代码时，主机的配置 ecs-9cc1 | 华东-上海一 | default
# 每个区域默认预置一个项目，以区域默认项目为单位授权的IAM用户可访问您帐号中该区域所有项目资源。
# 华东-上海一	| cn-east-3
DefaultProject = {
    "name": "cn-east-3",
    "id": None,
}

DefaultECS = None  # 缺省的 ECS 实例

API_Token = None        # 全局 Token 缓存


# 处理登录请求，并将获取到的 token
def process_huawei_cloud_auth(uid="agent", passwd=None):
    if passwd is None:
        # 检查环境变量是否给出了 HW_PASSWORD, 缺省值为 None
        passwd = os.environ.get("HW_PASSWORD", None)
    if passwd is None:
        raise PermissionError("Password is not set, change ENV[HW_PASSWORD]")
    else:
        # 检查是否有 shell 引入的 ' 或 ”
        if passwd[0] in ["'", '"']:
            passwd = passwd[1:-1]
    """
        获取 token 的方式
        POST https://iam.cn-north-1.myhuaweicloud.com/v3/auth/tokens
        {
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "domain": {
                                "name": "IAMDomain"        //IAM用户所属帐号名
                            },
                            "name": "IAMUser",             //IAM用户名
                            "password": "IAMPassword"      //IAM用户密码
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": "cn-north-1"               //项目名称
                    }
                }
            }
        }
    """
    # 借助 requests 库构造 获取 token 对应的请求
    # 构造请求的 body
    body = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {"name": "nzinfo"},
                        "name": uid,
                        "password": passwd,
                    }
                },
            },
            "scope": {"project": {"name": DefaultProject["name"]}},
        }
    }
    # 构造请求的 header
    headers = {"Content-Type": "application/json"}
    # 构造请求的 url
    url = "https://iam.{}/v3/auth/tokens?nocatalog=true".format(EndPoint)
    # 发送请求
    resp = requests.post(url, json=body, headers=headers)
    # print(resp.headers)
    # print(resp.text)

    if resp.status_code == 201:
        # 从响应的 header 中获取 token
        token = resp.headers.get("X-Subject-Token", None)
        return token
    else:
        raise PermissionError("Failed to get token, check your password. \nResponse: {}".format(resp.text))


def get_token(args):
    global API_Token
    global DefaultProject

    if API_Token is not None:
        return API_Token

    # 从当前目录的临时文件获取 token, 临时文件位置在 当前用户目录下的 ".hwc_token"
    token = None
    token_fname = os.path.join(os.path.expanduser("~"), ".hwc_token")
    if os.path.isfile(token_fname):
        with open(token_fname, "r") as fh:
            token = fh.read()
    if token is None:
        # 重新获取
        token = process_huawei_cloud_auth()
        # 保存到文件
        if token is not None:
            with open(token_fname, "w") as fh:
                fh.write(token)
    else:
        # print("using token cache file: {}".format(token_fname))
        pass

    # 验证 token 是否有效 & 同时读取 DefaultProject 的默认 Project ID, eg.4e5290be6648468dade2403942a3c57c
    # 获取项目ID的接口为“GET https://{Endpoint}/v3/projects”，其中{Endpoint}为IAM的终端节点
    url = "https://iam.{}/v3/projects".format(EndPoint)
    headers = {"Content-Type": "application/json", "X-Auth-Token": token}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        # 获取 projects id 的接口返回的是一个 json 数组，其中每个元素是一个 dict
        projects = resp.json().get("projects", [])
        for proj in projects:
            if proj.get("name", "") == DefaultProject["name"]:
                DefaultProject["id"] = proj.get("id", None)
        # 确认当前 token 有效，且 DefaultProject["id"] 不为 None
        # print("project_id", DefaultProject["id"])
        API_Token = token
        return token
    else:
        # 删除文件重新获取
        os.remove(token_fname)
        return get_token(args)


def list_ecs(args, list_servers=True):
    global DefaultECS

    def get_resp_ip(resp):
        # 从 resp 中获取 IP 地址 列表
        addresses = resp.get("addresses", {})
        if len(addresses) == 0:
            return ""
        else:
            ip_list = []
            for _, ips in addresses.items():
                for ip in ips:
                    if ip["version"] == '4':
                        # print(ip["addr"])
                        ip_list.append(ip["addr"])
            return ",".join(ip_list)

    token = get_token(args)
    # 获取所有的 ECS 实例 的 URL 说明在 https://support.huaweicloud.com/api-ecs/zh-cn_topic_0094148850.html
    # GET https://{endpoint}/v1/{project_id}/cloudservers/detail
    # 构造请求
    url = "https://ecs.{}/v1/{}/cloudservers/detail".format(EndPoint, "4e5290be6648468dade2403942a3c57c")
    headers = {"Content-Type": "application/json", "X-Auth-Token": token}
    resp = requests.get(url, headers=headers)
    # print(resp.text)
    # 读取 servers 列表，确定 default server
    servers = resp.json().get("servers", [])
    if len(servers) == 1:
        # 只有一个 server, 直接使用
        DefaultECS = {
            "id": servers[0]["id"],
            "name": servers[0]["name"],
            "ip": get_resp_ip(servers[0]),
        }

    # 输出 ecs 实例，用表格的形式
    if list_servers:
        print("ID\tName\tStatus\tIP")
        for server in servers:
            print("{}\t{}\t{}\t{}".format(
                server["id"], server["name"], server["status"], get_resp_ip(server)
            ))


def resize_ecs(token, instance_id, flavor_id):
    # expand_ecs 与 shrink_ecs 在 API 调用上相同，不同的只有实例规格的 ID .
    # Ref: https://support.huaweicloud.com/api-ecs/ecs_02_0210.html
    # 构造请求
    url = "https://ecs.{}/v1/{}/cloudservers/{}/resize".format(EndPoint, DefaultProject["id"], instance_id)
    headers = {"Content-Type": "application/json", "X-Auth-Token": token}

    # 构造请求的 body
    body = {
        "resize": {
            "flavorRef": flavor_id,
            "mode": "withStopServer",   # mode取值为withStopServer时，对开机状态的云服务器执行变更规格操作，
                                        # 系统自动对云服务器先执行关机，再变更规格，变更成功后再执行开机。

        }
    }
    # print("expand_ecs", DefaultECS)
    resp = requests.post(url, json=body, headers=headers)
    # print(resp.text)
    if resp.status_code == 200:
        # 返回的是一个 job_id
        job_id = resp.json().get("job_id", None)
        return job_id
    else:
        print(resp.text)
        return None


def query_job_status(token, job_id):
    # ref: https://support.huaweicloud.com/api-ecs/ecs_02_0901.html
    # GET https://{endpoint}/v1/{project_id}/jobs/{job_id}
    """
    GET https://{endpoint}/v1/{project_id}/jobs/{job_id}

    {
        "status": "SUCCESS",
        "entities": {
            "sub_jobs_total": 1,
            "sub_jobs": [
                {
                    "status": "SUCCESS",
                    "entities": {
                        "server_id": "bae51750-0089-41a1-9b18-5c777978ff6d"
                    },
                    "job_id": "2c9eb2c5544cbf6101544f0635672b60",
                    "job_type": "createSingleServer",
                    "begin_time": "2016-04-25T20:04:47.591Z",
                    "end_time": "2016-04-25T20:08:21.328Z",
                    "error_code": null,
                    "fail_reason": null
                }
            ]
        },
        "job_id": "2c9eb2c5544cbf6101544f0602af2b4f",
        "job_type": "createServer",
        "begin_time": "2016-04-25T20:04:34.604Z",
        "end_time": "2016-04-25T20:08:41.593Z",
        "error_code": null,
        "fail_reason": null
    }

    Job的状态。
        SUCCESS：成功。
        RUNNING：运行中。
        FAIL：失败。
        INIT：正在初始化。
        PENDING_PAYMENT : 包年/包月订单待支付。
    """
    # 构造状态查询请求
    url = "https://ecs.{}/v1/{}/jobs/{}".format(EndPoint, DefaultProject["id"], job_id)
    headers = {"Content-Type": "application/json", "X-Auth-Token": token}
    resp = requests.get(url, headers=headers)
    # print(resp.text)
    if resp.status_code == 200:
        # 返回的是一个 job_id
        job_status = resp.json().get("status", None)
        return job_status


def expand_ecs(args):
    if DefaultECS is None:
        list_ecs(args, list_servers=False)  # 确定 DefaultECS
    instance_id = args.instance_id
    if instance_id is None:
        instance_id = DefaultECS["id"]
    # 获取 token
    token = get_token(args)
    # c7.8xlarge.2  16 物理核(32vCPU)， 64G RAM
    job_id = resize_ecs(token, instance_id, "c7.8xlarge.2")
    # print(job_id)
    if job_id:
        print("waiting for job {} to finish...".format(job_id))
        while True:
            job_status = query_job_status(token, job_id)
            if job_status not in ["SUCCESS", "FAIL", "PENDING_PAYMENT"]:
                print("job {} is {}".format(job_id, job_status))
                time.sleep(5)
            else:
                break
        print("job {} is {}".format(job_id, job_status))


def shrink_ecs(args):
    if DefaultECS is None:
        list_ecs(args, list_servers=False)  # 确定 DefaultECS

    instance_id = args.instance_id
    if instance_id is None:
        instance_id = DefaultECS["id"]
    # 获取 token
    token = get_token(args)

    # 变更到 m7.large.8 2 vCPU 16G RAM
    job_id = resize_ecs(token, instance_id, "m7.large.8")
    if job_id:
        print("waiting for job {} to finish...".format(job_id))
        while True:
            job_status = query_job_status(token, job_id)
            if job_status not in ["SUCCESS", "FAIL", "PENDING_PAYMENT"]:
                print("job {} is {}".format(job_id, job_status))
                time.sleep(5)
            else:
                break
        print("job {} is {}".format(job_id, job_status))


def restart_ecs(args):
    # 借助 Fabric 远程启动诸服务
    # 暂时只支持 控制 DefaultECS
    # 获取 DefaultECS 的 公网 IP 地址
    if DefaultECS is None:
        list_ecs(args, list_servers=False)
    ip_list = DefaultECS["ip"].split(",")
    server_ip = None
    for ip in ip_list:
        if ip.startswith("10.") or ip.startswith("192.168"):
            # 内网 IP
            continue
        server_ip = ip
        break
    if server_ip is None:
        raise ValueError("No public IP found for server {}".format(DefaultECS["name"]))

    # 通过 Fabric 远程启动服务
    # Note, 也可借助 Ansible， 直接用 Fabric 更简单
    print("connecting to server {}".format(server_ip))
    user_password = os.environ.get("ECS_PASSWORD", None)
    if user_password is None:
        raise PermissionError("Password is not set, change ENV[ECS_PASSWORD]")

    conn = Connection(server_ip, user='llama', connect_kwargs={"password": user_password})
    # 启动 llm 服务
    conn.sudo("ls /root", password=user_password)   # 确保 sudo 不需要密码
    # 启动 tool server
    # python3 -m llama_cpp.server --model ./llama-2-7b-chat.ggmlv3.q8_0.bin --port 8000
    # OPENAI_API_KEY=../llama-2-7b-chat.ggmlv3.q8_0.bin OPENAI_API_BASE="http://127.0.0.1:8000/v1" conda run -n bmtools python host_local_tools.py
    # FIXME 调整为可用的 shell 脚本，并且借助 screen 启动
    # 需要等待确保 tool server 完全启动后，再启动 web
    # 启动 web
    # OPENAI_API_KEY=../llama-2-7b-chat.ggmlv3.q8_0.bin OPENAI_API_BASE="http://127.0.0.1:8000/v1" conda run -n bmtools python web_demo.py
    pass


def main():
    # 构成命令行参数，及其 subcommand, which are list, expand, shrink, restart
    parser = argparse.ArgumentParser(prog="hwc_tool", description="Huawei Cloud ECS Deploy Tool.")
    sub_parser = parser.add_subparsers(help="subcommands")
    parser_list = sub_parser.add_parser("list", help="list ecs.")
    parser_list.set_defaults(func=list_ecs)

    parser_expand = sub_parser.add_parser("expand", help="expand ecs.")
    # 可选的 instance_id
    parser_expand.add_argument("instance_id", nargs="?", help="ecs instance id.")
    parser_expand.set_defaults(func=expand_ecs)

    parser_shrink = sub_parser.add_parser("shrink", help="shrink ecs.")
    parser_shrink.add_argument("instance_id", nargs="?", help="ecs instance id.")
    parser_shrink.set_defaults(func=shrink_ecs)

    parser_restart = sub_parser.add_parser("restart", help="restart ecs.")
    parser_restart.add_argument("instance_id", nargs="?", help="ecs instance id.")
    parser_restart.set_defaults(func=restart_ecs)

    args = parser.parse_args()
    parser.add_help = True

    # 缺省 显示  help 信息
    if len(vars(args)) == 0:
        parser.print_help()
        return

    print(args)
    args.func(args)


if __name__ == "__main__":
    main()
