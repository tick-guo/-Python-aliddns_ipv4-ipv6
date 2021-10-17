from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkalidns.request.v20150109.DescribeSubDomainRecordsRequest import DescribeSubDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
import requests
from urllib.request import urlopen
import json
import logging
import datetime
import sys
import os
#切换到脚本所在目录
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))

ipv4_flag = 1  # 是否开启ipv4 ddns解析,1为开启，0为关闭
ipv6_flag = 1  # 是否开启ipv6 ddns解析,1为开启，0为关闭
accessKeyId = "accessKeyId"  # 将accessKeyId改成自己的accessKeyId
accessSecret = "accessSecret"  # 将accessSecret改成自己的accessSecret
domain = "zeruns.tech"  # 你的主域名
name_ipv4 = "blog"  # 要进行ipv4 ddns解析的子域名
name_ipv6 = "ipv6.test"  # 要进行ipv6 ddns解析的子域名
log_file_flag = 1  # 日志同时输出到文件,1为开启，0为关闭


logger = logging.getLogger('mylogger')
logger.setLevel(logging.INFO)
#控制台
log_handler = logging.StreamHandler(sys.stderr)#默认是sys.stderr
log_handler.setLevel(logging.INFO) 
log_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s"))
#文件
log_file_handler = logging.FileHandler('ip.log')
log_file_handler.setLevel(logging.INFO)
log_file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
#添加生效
logger.addHandler(log_handler)
if log_file_flag == 1:
    logger.addHandler(log_file_handler)
 
#logger.debug('debug message')
#logger.info('info message')
#logger.warning('warning message')
#logger.error('error message')
#logger.critical('critical message')

logger.info('程序开始')

client = AcsClient(accessKeyId, accessSecret, 'cn-hangzhou')

def update(RecordId, RR, Type, Value):  # 修改域名解析记录
    from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
    request = UpdateDomainRecordRequest()
    request.set_accept_format('json')
    request.set_RecordId(RecordId)
    request.set_RR(RR)
    request.set_Type(Type)
    request.set_Value(Value)
    response = client.do_action_with_exception(request)


def add(DomainName, RR, Type, Value):  # 添加新的域名解析记录
    from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
    request = AddDomainRecordRequest()
    request.set_accept_format('json')
    request.set_DomainName(DomainName)
    request.set_RR(RR)  # https://blog.zeruns.tech
    request.set_Type(Type)
    request.set_Value(Value)    
    response = client.do_action_with_exception(request)


if ipv4_flag == 1:
    request = DescribeSubDomainRecordsRequest()
    request.set_accept_format('json')
    request.set_DomainName(domain)
    request.set_SubDomain(name_ipv4 + '.' + domain)
    request.set_Type("A")
    response = client.do_action_with_exception(request)  # 获取域名解析记录列表
    domain_list = json.loads(response)  # 将返回的JSON数据转化为Python能识别的

    ip = urlopen('https://api-ipv4.ip.sb/ip').read()  # 使用IP.SB的接口获取ipv4地址
    ipv4 = str(ip, encoding='utf-8')
    logger.info("获取到IPv4地址：%s" % ipv4)

    if domain_list['TotalCount'] == 0:
        add(domain, name_ipv4, "A", ipv4)
        logger.info("新建域名解析成功")
    elif domain_list['TotalCount'] == 1:
        if domain_list['DomainRecords']['Record'][0]['Value'].strip() != ipv4.strip():
            update(domain_list['DomainRecords']['Record'][0]['RecordId'], name_ipv4, "A", ipv4)
            logger.info("修改域名解析成功")
        else:  # https://blog.zeruns.tech
            logger.info("IPv4地址没变")
    elif domain_list['TotalCount'] > 1:
        from aliyunsdkalidns.request.v20150109.DeleteSubDomainRecordsRequest import DeleteSubDomainRecordsRequest
        request = DeleteSubDomainRecordsRequest()
        request.set_accept_format('json')
        request.set_DomainName(domain)  # https://blog.zeruns.tech
        request.set_RR(name_ipv4)
        request.set_Type("A") 
        response = client.do_action_with_exception(request)
        add(domain, name_ipv4, "A", ipv4)
        logger.info("修改域名解析成功")


if ipv6_flag == 1:
    request = DescribeSubDomainRecordsRequest()
    request.set_accept_format('json')
    request.set_DomainName(domain)
    request.set_SubDomain(name_ipv6 + '.' + domain)
    request.set_Type("AAAA")
    response = client.do_action_with_exception(request)  # 获取域名解析记录列表
    domain_list = json.loads(response)  # 将返回的JSON数据转化为Python能识别的

    ip = urlopen('https://api-ipv6.ip.sb/ip').read()  # 使用IP.SB的接口获取ipv6地址
    ipv6 = str(ip, encoding='utf-8')
    logger.info("获取到IPv6地址：%s" % ipv6)

    if domain_list['TotalCount'] == 0:
        add(domain, name_ipv6, "AAAA", ipv6)
        logger.info("新建域名解析成功")
    elif domain_list['TotalCount'] == 1:
        if domain_list['DomainRecords']['Record'][0]['Value'].strip() != ipv6.strip():
            update(domain_list['DomainRecords']['Record'][0]['RecordId'], name_ipv6, "AAAA", ipv6)
            logger.info("修改域名解析成功")
        else:  # https://blog.zeruns.tech
            logger.info("IPv6地址没变")
    elif domain_list['TotalCount'] > 1:
        from aliyunsdkalidns.request.v20150109.DeleteSubDomainRecordsRequest import DeleteSubDomainRecordsRequest
        request = DeleteSubDomainRecordsRequest()
        request.set_accept_format('json')
        request.set_DomainName(domain)
        request.set_RR(name_ipv6)  # https://blog.zeruns.tech
        request.set_Type("AAAA") 
        response = client.do_action_with_exception(request)
        add(domain, name_ipv6, "AAAA", ipv6)
        logger.info("修改域名解析成功")
