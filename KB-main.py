# -*- coding: utf-8 -*-
import xlrd
import json
import requests

#######################################   generate data ##################################################################


def format_data_json(s_prefix, s_names, s_flag, p_prefix, p_name, p_flag, o_prefix, o_names, o_flag, p_attr={}):
    ##组成对应的json格式数据
    s_len = len(s_names)
    o_len = len(o_names)
    if s_len != o_len:
        exit("s_len != o_len!")
    if s_len == 0:
        exit("s_names is null!")
    # if p_prefix == "property":
    #     tmp_s=[]
    #     tmp_o=[]
    #     for i,value in enumerate(s_names):
    #         if value not in tmp_s:
    #             tmp_s.append(value)
    #             tmp_o.append(o_names[i])
    #         else if o_
    result = []
    for i in range(0, s_len):
        s = {}
        s["prefix"] = s_prefix
        s["name"] = s_names[i]
        s["flag"] = s_flag
        p = {}
        p["prefix"] = p_prefix
        p["name"] = p_name
        p["flag"] = p_flag
        o = {}
        o["prefix"] = o_prefix
        o["name"] = o_names[i]
        o["flag"] = o_flag
        if p_attr:
            attr = {j: p_attr[j][i] for j in p_attr}
        else:
            attr = {}
        data = {}
        data["s"] = s
        data["p"] = p
        data["o"] = o
        data["attr"] = attr
        # print(data)
        if data not in result:
            result.append(data)
    #print(result)
    # print(result)
    # result_json = json.dumps(result,ensure_ascii=False,sort_keys=False,indent=4,separators=(",", ":"))
    result_json = result
    return result_json


def get_triple(xls_file, s_prefix, s_column, s_flag, p_prefix, p_name, p_flag, o_prefix, o_column, o_flag, p_attr={}):
    ## 根据编号从Excel中读取数据，并删除有空值的行
    if xls_file == "":
        exit("file in null!")
    s = []
    o = []
    if isinstance(s_column, str) and isinstance(o_column, str):
        tmp_s = [s_column]
        tmp_o = [o_column]
        return format_data_json(s_prefix, tmp_s,s_flag, p_prefix, p_name, p_flag, o_prefix, tmp_o, o_flag)

    if isinstance(s_column, str) and isinstance(o_column, int):
        tmp_o = xls_file.col_values(o_column)
        for i in range(1, xls_file.nrows):
            if tmp_o[i] != "":
                o.append(tmp_o[i])
        s = [o_column] * len(o)
        return format_data_json(s_prefix, s, s_flag, p_prefix, p_name, p_flag, o_prefix, o, o_flag)

    if isinstance(s_column, int) and isinstance(o_column, str):
        tmp_s = xls_file.col_values(s_column)
        for i in range(1, xls_file.nrows):
            if tmp_s[i] != "":
                s.append(tmp_s[i])
        o = [o_column]*len(s)
        return format_data_json(s_prefix, s, s_flag, p_prefix, p_name, p_flag, o_prefix, o, o_flag)

    tmp_s = xls_file.col_values(s_column)
    tmp_o = xls_file.col_values(o_column)
    if p_attr:
        p = {j:[] for j in p_attr}
        for i in range(1, xls_file.nrows):   #除去有一个值为空的行
            if tmp_s[i] != "" and tmp_o[i] != "":
                s.append(tmp_s[i])
                o.append(tmp_o[i])
                for j in p_attr:
                    p[j].append(xls_file.cell(i,p_attr[j]).value)
        ret = format_data_json(s_prefix, s, s_flag, p_prefix, p_name, p_flag, o_prefix, o, o_flag, p)
    else:
        for i in range(1, xls_file.nrows):   #除去有一个值为空的行
            if tmp_s[i] != "" and tmp_o[i] != "":
                s.append(tmp_s[i])
                o.append(tmp_o[i])
        ret = format_data_json(s_prefix, s, s_flag, p_prefix, p_name, p_flag, o_prefix, o, o_flag)
    return ret


def generate_data():
    ##从execl中批量读取数据，生成指定的Json格式
    data_1 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\HTTP木马检测-HTTP木马.xls")
    table_1 = data_1.sheet_by_index(0)
    # print(table.nrows)
    # name=table.cell(10,2).value
    # 2:文件名
    file1_1 = get_triple(table_1, "entity", 2, "", "property", "size", "", "literal", 19, "")
    file1_2 = get_triple(table_1, "entity", 2, "", "property", "文件MD5", "", "literal", 20, "")
    file1_3 = get_triple(table_1, "entity", 2, "", "property", "URL", "", "literal", 22, "")
    file1_4 = get_triple(table_1, "entity", 2, "", "property", "访问次数", "", "literal", 18, "")
    # 0:节点 , 16:静态结果， 17：异常类型
    file1_5 = get_triple(table_1, "entity", 0, "", "relationship", "捕获", "", "entity", 2, "", {"Capture_time":1, "InputDB_time":21})
    file1_6 = get_triple(table_1, "entity", 2, "", "relationship", "ErrorType", "", "entity", 17, "", {"Risk_value":3})
    file1_7 = get_triple(table_1, "entity", 2, "", "relationship", "源IP", "", "entity", 5, "")
    file1_8 = get_triple(table_1, "entity", 2, "", "relationship", "目的IP", "", "entity", 8, "")
    file1_9 = get_triple(table_1, "entity", 2, "", "relationship", "oneOf", "owl", "entity", 16, "", {"Risk_value":15})

    file1_10 = get_triple(table_1, "entity", 5, "", "relationship", "国家", "", "entity", 6, "")
    file1_11 = get_triple(table_1, "entity", 5, "", "property", "地理位置", "", "literal", 7, "")
    file1_12 = get_triple(table_1, "entity", 8, "", "relationship", "国家", "", "entity", 10, "")
    file1_13 = get_triple(table_1, "entity", 8, "", "property", "地理位置", "", "literal", 11, "")

    file1_14 = get_triple(table_1, "entity", 2, "", "relationship", "type", "rdf", "Ontology", "文件", "")
    file1_15 = get_triple(table_1, "entity", 17, "", "relationship", "type", "rdf", "Ontology", "文件异常", "")
    file1_16 = get_triple(table_1, "entity", 16, "", "relationship", "subClassOf", "rdfs", "Ontology", "木马类", "")
    file1_17 = get_triple(table_1, "Ontology", "木马类", "", "relationship", "subClassOf", "rdfs", "Ontology", "网络异常行为", "")

    # print(json.dumps(file1,ensure_ascii=False,sort_keys=True,indent=4,separators=(",", ":")))
    # file1__json = json.dumps(file1_,ensure_ascii=False)
    file1 = file1_1 + file1_2 + file1_3 + file1_4 + file1_5  +file1_6 + file1_7 + file1_8 + file1_9 + file1_10 + \
        file1_11 +  file1_12 + file1_13 + file1_14 + file1_15 + file1_16 + file1_17

    data_2 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\HTTP木马检测-文件类型伪造.xls")
    table_2 = data_2.sheet_by_index(0)

    file2_1 = get_triple(table_2, "entity", 0, "", "relationship", "捕获", "", "entity", 2, "", {"Capture_time":1, "InputDB_time":19})
    file2_2 = get_triple(table_2, "entity", 2, "", "property", "size", "", "literal", 15, "")
    file2_3 = get_triple(table_2, "entity", 2, "", "property", "MD5", "", "literal", 16, "")
    file2_4 = get_triple(table_2, "entity", 2, "", "property", "访问次数", "", "literal", 4, "")

    file2_5 = get_triple(table_2, "entity", 2, "", "relationship", "源IP", "", "entity", 6, "")
    file2_6 = get_triple(table_2, "entity", 2, "", "relationship", "目的IP", "", "entity", 9, "")

    file2_7 = get_triple(table_2, "entity", 6, "", "relationship", "国家", "", "entity", 7, "")
    file2_8 = get_triple(table_2, "entity", 9, "", "relationship", "国家", "", "entity", 11, "")
    file2_9 = get_triple(table_2, "entity", 6, "", "property", "地理位置", "", "literal", 8, "")
    file2_10 = get_triple(table_2, "entity", 9, "", "property", "地理位置", "", "literal", 12, "")

    file2_11 = get_triple(table_2, "entity", 2, "", "relationship", "ErrorType", "", "entity", 17, "", {"Risk_value": 5})
    file2_12 = get_triple(table_2, "entity", 2, "", "relationship", "oneOf", "owl", "entity", 14, "", {"Risk_value": 13})

    file2_13 = get_triple(table_2, "entity", 2, "", "relationship", "type", "rdf", "Ontology", "文件", "")
    file2_14 = get_triple(table_2, "entity", 17, "", "relationship", "type", "rdf", "Ontology", "文件异常", "")
    file2_15 = get_triple(table_2, "entity", 14, "", "relationship", "subClassOf", "rdfs", "Ontology", "木马类", "")

    file2 = file2_1 + file2_2 + file2_3 + file2_4 + file2_5  +file2_6 + file2_7 + file2_8 + file2_9 + file2_10 + \
        file2_11 +  file2_12 + file2_13 + file2_14 + file2_15

    data_3 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\Web渗透-威胁检测.xls")
    table_3 = data_3.sheet_by_index(0)
    file3_1 = get_triple(table_3, "entity", 1, "", "relationship", "源IP", "", "entity", 3, "")
    file3_2 = get_triple(table_3, "entity", 1, "", "relationship", "目的IP", "", "entity", 2, "")
    file3_3 = get_triple(table_3, "entity", 1, "", "property", "风险等级", "", "literal", 6, "")
    file3_4 = get_triple(table_3, "entity", 1, "", "property", "攻击载荷", "", "literal", 7, "")
    file3_5 = get_triple(table_3, "entity", 1, "", "relationship", "oneOf", "owl", "entity", 5, "")

    file3_6 = get_triple(table_3, "entity", 3, "", "property", "地理位置", "", "literal", 4, "")
    file3_7 = get_triple(table_3, "entity", 3, "", "property", "是否恶意", "", "literal", 9, "")

    file3_8 = get_triple(table_3, "entity", 5, "", "relationship", "type", "rdf", "Ontology", "渗透攻击类", "")
    file3_9 = get_triple(table_3, "Ontology", "渗透攻击类", "", "relationship", "subClassOf", "rdfs", "Ontology", "网络异常行为", "")
    file3_10 = get_triple(table_3, "entity", 0, "", "relationship", "捕获", "", "entity", 1, "")

    file3 = file3_1 + file3_2 + file3_3 + file3_4 + file3_5 + file3_6 + file3_7 + file3_8 + file3_9 + file3_10


    data_4 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\钓鱼邮件检测-钓鱼邮件.xls")
    table_4 = data_4.sheet_by_index(0)

    file4_1 = get_triple(table_4, "entity", 3, "", "relationship", "源IP", "", "entity", 8, "")
    file4_2 = get_triple(table_4, "entity", 8, "", "relationship", "国家", "", "entity", 11, "")
    file4_3 = get_triple(table_4, "entity", 8, "", "property", "地理位置", "", "literal", 12, "")

    file4_4 = get_triple(table_4, "entity", 3, "", "relationship", "目的IP", "", "entity", 13, "")
    file4_5 = get_triple(table_4, "entity", 13, "", "relationship", "国家", "", "entity", 16, "")
    file4_6 = get_triple(table_4, "entity", 13, "", "property", "地理位置", "", "literal", 17, "")

    file4_7 = get_triple(table_4, "entity", 3, "", "relationship", "发送IP", "", "entity", 24, "")
    file4_8 = get_triple(table_4, "entity", 24, "", "relationship", "国家", "", "entity", 26, "")
    file4_9 = get_triple(table_4, "entity", 24, "", "property", "地理位置", "", "literal", 25, "")

    file4_10 = get_triple(table_4, "entity", 3, "", "property", "邮件主题", "", "literal", 5, "")
    file4_11 = get_triple(table_4, "entity", 3, "", "property", "邮件大小", "", "literal", 41, "")
    file4_12 = get_triple(table_4, "entity", 3, "", "property", "协议类型", "", "literal", 27, "")
    file4_13 = get_triple(table_4, "entity", 3, "", "property", "邮件语种", "", "literal", 42, "")
    file4_14 = get_triple(table_4, "entity", 3, "", "property", "主题编码", "", "literal", 29, "")
    file4_15 = get_triple(table_4, "entity", 3, "", "property", "发送时间", "", "literal", 1, "")
    file4_16 = get_triple(table_4, "entity", 3, "", "property", "接受时间", "", "literal", 28, "")

    file4_17 = get_triple(table_4, "entity", 3, "", "relationship", "钓鱼外链", "", "entity", 4, "")
    file4_18 = get_triple(table_4, "entity", 4, "", "property", "外链大小", "", "literal", 53, "")
    file4_19 = get_triple(table_4, "entity", 4, "", "property", "外链位置", "", "literal", 47, "")
    file4_20 = get_triple(table_4, "entity", 4, "", "property", "钓鱼顶级域名", "", "literal", 45, "")

    file4_21 = get_triple(table_4, "entity", 3, "", "relationship", "发件邮箱", "", "entity", 18, "")
    file4_22 = get_triple(table_4, "entity", 3, "", "relationship", "收件邮箱", "", "entity", 19, "")
    file4_23 = get_triple(table_4, "entity", 3, "", "relationship", "收件邮箱", "", "entity", 20, "")

    file4_24 = get_triple(table_4, "entity", 0, "", "relationship", "捕获", "", "entity", 3, "", {"Capture_time":23, "InputDB_time":2})
    file4_25 = get_triple(table_4, "entity", 3, "", "relationship", "oneOf", "owl", "Ontology", "钓鱼邮件", "", {"Risk_level":6,"Status":7})
    file4_26 = get_triple(table_4, "Ontology", "钓鱼邮件", "", "relationship", "subClassOf", "rdfs", "Ontology", "网络异常行为","")

    file4 = file4_1 + file4_2 + file4_3 + file4_4 + file4_5 + file4_6 + file4_7 + file4_8 + file4_9 + file4_10 + file4_11 + file4_12 + \
            file4_13 + file4_14 + file4_15 + file4_16 + file4_17 + file4_18 + file4_19 + file4_20 + file4_21 + file4_22 + file4_23 + \
            file4_24 + file4_25 + file4_26

    data_5 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\木马邮件检测-木马邮件.xls")
    table_5 = data_5.sheet_by_index(0)

    file5_1 = get_triple(table_5, "entity", 3, "", "relationship", "源IP", "", "entity", 5, "")
   # file5_2 = get_triple(table_5, "entity", 5, "", "relationship", "国家", "", "entity", 11, "")
    file5_3 = get_triple(table_5, "entity", 5, "", "property", "地理位置", "", "literal", 7, "")

    file5_4 = get_triple(table_5, "entity", 3, "", "relationship", "目的IP", "", "entity", 9, "")
    file5_5 = get_triple(table_5, "entity", 9, "", "relationship", "国家", "", "entity", 13, "")
    file5_6 = get_triple(table_5, "entity", 13, "", "property", "地理位置", "", "literal", 18, "")

    file5_7 = get_triple(table_5, "entity", 3, "", "relationship", "发送IP", "", "entity", 16, "")
    #file5_8 = get_triple(table_5, "entity", 16, "", "relationship", "国家", "", "entity", 26, "")
    file5_9 = get_triple(table_5, "entity", 16, "", "property", "地理位置", "", "literal", 17, "")

    file5_10 = get_triple(table_5, "entity", 3, "", "property", "邮件主题", "", "literal", 0, "")
    file5_11 = get_triple(table_5, "entity", 3, "", "property", "邮件大小", "", "literal", 38, "")
    file5_12 = get_triple(table_5, "entity", 3, "", "property", "协议类型", "", "literal", 19, "")
    file5_13 = get_triple(table_5, "entity", 3, "", "property", "邮件语种", "", "literal", 39, "")
    file5_14 = get_triple(table_5, "entity", 3, "", "property", "主题编码", "", "literal", 21, "")
    file5_15 = get_triple(table_5, "entity", 3, "", "property", "发送时间", "", "literal", 11, "")
    file5_16 = get_triple(table_5, "entity", 3, "", "property", "接受时间", "", "literal", 20, "")
    file5_17 = get_triple(table_5, "entity", 3, "", "property", "有附件", "", "literal", 1, "")

    file5_18 = get_triple(table_5, "entity", 3, "", "relationship", "发件邮箱", "", "entity", 32, "")
    file5_19 = get_triple(table_5, "entity", 3, "", "relationship", "收件邮箱", "", "entity", 41, "")
    file5_20 = get_triple(table_5, "entity", 3, "", "relationship", "真实发件邮箱", "", "entity", 23, "")
    file5_21 = get_triple(table_5, "entity", 3, "", "relationship", "回复邮箱", "", "entity", 35, "")
    file5_25 = get_triple(table_5, "entity", 3, "", "relationship", "oneof", "owl", "Ontology", "邮件", "")

    file5_22 = get_triple(table_5, "entity", 26, "", "relationship", "捕获", "", "entity", 3, "", \
                          {"Capture_time": 15, "InputDB_time": 22})
    file5_23 = get_triple(table_5, "entity", 3, "", "relationship", "oneOf", "owl", "Ontology", 2, "", \
                          {"Risk_level": 4, "Download": 46})
    file5_24 = get_triple(table_5, "Ontology", 2, "", "relationship", "subClassOf", "rdfs", "Ontology", \
                          "网络异常行为", "")

    file5 = file5_1 + file5_3 + file5_4 + file5_5 + file5_6 + file5_7 + file5_9 + file5_10 + file5_11 + file5_12 + \
            file5_13 + file5_14 + file5_15 + file5_16 + file5_17 + file5_18 + file5_19 + file5_20 + file5_21 + \
            file5_22 + file5_23 + file5_24


    data_6 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\木马邮件检测-木马附件.xls")
    table_6 = data_6.sheet_by_index(0)

    file6_1 = get_triple(table_6, "entity", 3, "", "property", "附件主题", "", "literal", 1, "")
    file6_2 = get_triple(table_6, "entity", 3, "", "property", "附件名称", "", "literal", 2, "")
    file6_3 = get_triple(table_6, "entity", 3, "", "property", "附件类型", "", "literal", 12, "")
    file6_4 = get_triple(table_6, "entity", 3, "", "property", "附件大小", "", "literal", 13, "")
    file6_5 = get_triple(table_6, "entity", 3, "", "property", "附件MD5", "", "literal", 17, "")
    file6_6 = get_triple(table_6, "entity", 3, "", "property", "访问数量", "", "literal", 18, "")
    file6_7 = get_triple(table_6, "entity", 3, "", "property", "语言类型", "", "literal", 19, "")

    file6_8 = get_triple(table_6, "entity", 24, "", "relationship", "附件", "", "entity", 3, "")
    file6_9 = get_triple(table_6, "entity", 0, "", "relationship", "捕获", "", "entity", 3, "", \
                          {"Capture_time": 34, "InputDB_time": 20})
    file6_10 = get_triple(table_6, "entity", 3, "", "relationship", "oneOf", "owl", "Ontology", 8, "", \
                          {"Risk_level": 4})
    file6_11 = get_triple(table_6, "Ontology", 8, "", "relationship", "subClassOf", "rdfs", "Ontology", \
                          "网络异常行为", "")

    file6 = file6_1 + file6_2 + file6_3 + file6_4 + file6_5 + file6_6 + file6_7 +  file6_8 + file6_9 + file6_10 + \
            file6_11

    data_7 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\受控邮箱检测-邮箱日志.xls")
    table_7= data_7.sheet_by_index(0)

    file7_1 = get_triple(table_7, "entity", 1, "", "property", "登陆时间", "", "literal", 4, "")
    file7_2 = get_triple(table_7, "entity", 1, "", "property", "登陆类型", "", "literal", 15, "")
    file7_3 = get_triple(table_7, "entity", 1, "", "property", "登陆密码", "", "literal", 17, "")
    file7_4 = get_triple(table_7, "entity", 1, "", "property", "登陆状态", "", "literal", 18, "")
    file7_5 = get_triple(table_7, "entity", 1, "", "property", "状态描述", "", "literal", 20, "")
    file7_6 = get_triple(table_7, "entity", 1, "", "property", "数据来源", "", "literal", 22, "")
    file7_7 = get_triple(table_7, "entity", 1, "", "property", "Session号", "", "literal", 19, "")

    file7_8 = get_triple(table_7, "entity", 1, "", "relationship", "登陆IP", "", "entity", 5, "")
    file7_9 = get_triple(table_7, "entity", 5, "", "relationship", "国家", "", "entity", 8, "")
    file7_10 = get_triple(table_7, "entity", 5, "", "property", "地理位置", "", "entity", 9, "")

    file7_11 = get_triple(table_7, "entity", 1, "", "relationship", "目的IP", "", "entity", 10, "")
    file7_12 = get_triple(table_7, "entity", 10, "", "relationship", "国家", "", "entity", 13, "")
    file7_13 = get_triple(table_7, "entity", 10, "", "property", "地理位置", "", "entity", 14, "")

    file7_14 = get_triple(table_7, "entity", 1, "", "relationship", "登陆邮箱", "", "entity", 2, "")

    file7_15 = get_triple(table_7, "entity", 0, "", "relationship", "捕获", "", "entity", 1, "", \
                         {"Capture_time": 30, "InputDB_time": 16})

    file7 = file7_1 + file7_2 + file7_3 + file7_4 + file7_5 + file7_6 + file7_7 + file7_8 + file7_9 + file7_10 + \
            file7_11 + file7_12 + file7_13 + file7_14 + file7_15

    data_8 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\恶意码址检测-恶意链接.xls")
    table_8= data_8.sheet_by_index(0)

    file8_1 = get_triple(table_8, "entity", 7, "", "relationship", "国家", "", "entity", 8, "")
    file8_2 = get_triple(table_8, "entity", 7, "", "property", "地理位置", "", "literal", 9, "")

    file8_3 = get_triple(table_8, "entity", 10, "", "relationship", "国家", "", "entity", 12, "")
    file8_4 = get_triple(table_8, "entity", 10, "", "property", "地理位置", "", "literal", 13, "")
    file8_5 = get_triple(table_8, "entity", 10, "", "property", "恶意链接", "", "literal", 3, "", \
                         {"Capture_time": 1, "InputDB_time": 2})

    file8 = file8_1 + file8_2 + file8_3 + file8_4 + file8_5

    data_9 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\远程控制检测-远程控制检测.xls")
    table_9 = data_9.sheet_by_index(0)

    file9_1 = get_triple(table_9, "entity", 1, "", "property", "登陆状态", "", "literal", 3, "")
    file9_2 = get_triple(table_9, "entity", 1, "", "property", "交互数据", "", "literal", 6, "")
    file9_3 = get_triple(table_9, "entity", 1, "", "property", "检测结果", "", "literal", 7, "")
    file9_4 = get_triple(table_9, "entity", 1, "", "property", "远程类型", "", "literal", 8, "")
    file9_5 = get_triple(table_9, "entity", 1, "", "property", "连接时长", "", "literal", 17, "")

    file9_6 = get_triple(table_9, "entity", 1, "", "relationship", "源IP", "", "entity", 9, "")
    file9_7 = get_triple(table_9, "entity", 9, "", "relationship", "国家", "", "entity", 11, "")
    file9_8 = get_triple(table_9, "entity", 9, "", "property", "地理位置", "", "entity", 12, "")

    file9_9 = get_triple(table_9, "entity", 1, "", "relationship", "目的IP", "", "entity", 13, "")
    file9_10 = get_triple(table_9, "entity", 13, "", "relationship", "国家", "", "entity", 15, "")
    file9_11 = get_triple(table_9, "entity", 13, "", "property", "地理位置", "", "entity", 16, "")

    file9_12 = get_triple(table_9, "entity", 0, "", "relationship", "捕获", "", "entity", 1, "", \
                          {"Capture_time": 2, "InputDB_time": 20})

    file9_13 = get_triple(table_9, "Ontology", 1, "", "relationship", "subClassOf", "rdfs", "Ontology", \
                          "网络异常行为", "")

    file9 = file9_1 + file9_2 + file9_3 + file9_4 + file9_5 + file9_6 + file9_7 + file9_8 + file9_9 + file9_10 + \
            file9_11 + file9_12 + file9_13

    data_10 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\异常通信检测-HTTPSHELL.xls")
    table_10 = data_10.sheet_by_index(0)

    file10_1 = get_triple(table_10, "entity", 1, "", "property", "Shell命令", "", "literal", 3, "")
    file10_2 = get_triple(table_10, "entity", 1, "", "property", "风险值", "", "literal", 6, "")
    
    file10_3 = get_triple(table_10, "entity", 1, "", "property", "源端口", "", "literal", 8, "")
    file10_4 = get_triple(table_10, "entity", 1, "", "property", "源MAC", "", "literal", 9, "")
    file10_5 = get_triple(table_10, "entity", 1, "", "property", "目的端口", "", "literal", 13, "")
    file10_6 = get_triple(table_10, "entity", 1, "", "property", "目的MAC", "", "literal", 14, "")
    
    file10_7 = get_triple(table_10, "entity", 1, "", "relationship", "应答服务器", "", "entity", 4, "")
    file10_8 = get_triple(table_10, "entity", 1, "", "relationship", "源IP", "", "entity", 7, "")
    file10_9 = get_triple(table_10, "entity", 7, "", "relationship", "国家", "", "entity", 10, "")
    file10_10 = get_triple(table_10, "entity", 7, "", "property", "地理位置", "", "entity", 11, "")

    file10_11 = get_triple(table_10, "entity", 1, "", "relationship", "目的IP", "", "entity", 12, "")
    file10_12 = get_triple(table_10, "entity", 12, "", "relationship", "国家", "", "entity", 15, "")
    file10_13 = get_triple(table_10, "entity", 12, "", "property", "地理位置", "", "entity", 16, "")

    file10_14 = get_triple(table_10, "entity", 0, "", "relationship", "捕获", "", "entity", 1, "", \
                          {"Capture_time": 2, "InputDB_time": 17})

    file10_15 = get_triple(table_10, "Ontology", 1, "", "relationship", "subClassOf", "rdfs", "Ontology", \
                          "网络异常行为", "")

    file10 = file10_1 + file10_2 + file10_3 + file10_4 + file10_5 + file10_6 + file10_7 + file10_8 + file10_9 + file10_10 + \
            file10_11 + file10_12 + file10_13 + file10_14 + file10_15

    data_11 = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\异常通信检测-明文SHELL.xls")
    table_11 = data_11.sheet_by_index(0)

    file11_1 = get_triple(table_11, "entity", 1, "", "property", "风险等级", "", "literal", 4, "")
    file11_2 = get_triple(table_11, "entity", 1, "", "property", "下载连接", "", "literal", 5, "")
    file11_3 = get_triple(table_11, "entity", 1, "", "property", "命中命令", "", "literal", 6, "")
    file11_4 = get_triple(table_11, "entity", 1, "", "property", "会话个数", "", "literal", 17, "")
    file11_5 = get_triple(table_11, "entity", 1, "", "property", "持续时间", "", "literal", 18, "")
    file11_6 = get_triple(table_11, "entity", 1, "", "property", "包文件大小", "", "literal", 19, "")
    file11_7 = get_triple(table_11, "entity", 1, "", "property", "流量协议", "", "literal", 20, "")
    file11_8 = get_triple(table_11, "entity", 1, "", "property", "是否回复", "", "literal", 21, "")
    file11_9 = get_triple(table_11, "entity", 1, "", "property", "前50会话流量", "", "literal", 22, "")

    file11_10 = get_triple(table_11, "entity", 1, "", "property", "源端口", "", "literal", 8, "")
    file11_11 = get_triple(table_11, "entity", 1, "", "property", "源MAC", "", "literal", 9, "")
    file11_12 = get_triple(table_11, "entity", 1, "", "property", "目的端口", "", "literal", 13, "")
    file11_13 = get_triple(table_11, "entity", 1, "", "property", "目的MAC", "", "literal", 14, "")

    file11_14 = get_triple(table_11, "entity", 1, "", "relationship", "源IP", "", "entity", 7, "")
    file11_15 = get_triple(table_11, "entity", 7, "", "relationship", "国家", "", "entity", 10, "")
    file11_16 = get_triple(table_11, "entity", 7, "", "property", "地理位置", "", "entity", 11, "")

    file11_17 = get_triple(table_11, "entity", 1, "", "relationship", "目的IP", "", "entity", 12, "")
    file11_18 = get_triple(table_11, "entity", 12, "", "relationship", "国家", "", "entity", 15, "")
    file11_19 = get_triple(table_11, "entity", 12, "", "property", "地理位置", "", "entity", 16, "")

    file11_20 = get_triple(table_11, "entity", 0, "", "relationship", "捕获", "", "entity", 1, "", \
                           {"Capture_time": 2, "InputDB_time": 3})

    file11_21 = get_triple(table_11, "Ontology", 1, "", "relationship", "subClassOf", "rdfs", "Ontology", \
                           "网络异常行为", "")

    file11 = file11_1 + file11_2 + file11_3 + file11_4 + file11_5 + file11_6 + file11_7 + file11_8 + file11_9 + \
             file11_10 + file11_11 + file11_12 + file11_13 + file11_14 + file11_15 + file11_16 + file11_17 + \
             file11_18 + file11_19 + file11_20  + file11_21

    result_json = file1 + file2 + file3 + file5 + file6 + file7 +file8 + file9 + file10 + file11
    #result_json = file1 + file2
    #result_json = file11
    return result_json

###########################################   edit node ################################################################


def add_node():
    url = "http://10.38.7.90:9876/allegro/addrdf/add"
    headers = {"Accept": "appllication/json"}
    json_data = {
        "s": {
            "prefix": "entity",
            "name": "路由器007",
            "flag": ""
        },
        "p": {
            "prefix": "relationship",
            "name": "connectTo",
            "flag": ""
        },
        "o": {
            "prefix": "entity",
            "name": "路由器002",
            "flag": ""
        },
        "attr": {
        }
    }
    response = requests.post(url, json=json_data, headers="")
    print(response.text)
    print(response.status_code)
    return "success!"


def add_nodes(dt):
    url = "http://10.38.7.90:9876/allegro/addrdf/addmore"
    header = {'content-type': 'appllication/json'}
   # print(dt)
   # print(js_data)
   # print(json.dumps(js_data))
    response = requests.post(url, json=dt, headers="")
    print(response.text)
    print(response.status_code)
    return "success!"


def del_all():
    url = "http://10.38.7.90:9876/allegro/addrdf/clear"
    response = requests.get(url, headers="")
    print(response.text)
    print(response.status_code)
    return "success!"

#######################################   get source ##################################################################


def get_all():
    url = "http://10.38.7.90:9876/allegro/deliver/listallattr?"
    pa = {'format': 'long'}
    head = {'Accept': 'appllication/json'}
    response = requests.get(url, params=pa, headers="")
    print(response.text)
    # print(response.content)
    print(response.status_code)
    print(response.url)
    return "success!"


def get_owl():
    url = "http://10.38.7.90:9876/allegro/deliver/schema"
    pa = {'format': 'long'}
    header = {"Accept": "appllication/json"}
    response = requests.get(url, params=pa, headers="")
    a = json.loads(response.text)
    # json.dumps(response.text, sort_keys=True, indent=4, separators=(',', ':'))
    print(a)
    # print(response.content)
    with open("tmp.txt ", "w") as fp:
        fp.write(response.text)
    print(response.status_code)
    # print(response.url)
    return "success!"


def get_repository():
    url = "http://10.38.7.90:9876/allegro/file/exportrepository"
    headers = {"Accept": "appllication/json"}
    json_data = {
        "catalog": "/",
        "repository": "liuzhengjun",
        "type": "RDF/XML"
    }
    response = requests.post(url, json=json_data, headers="")

    print(response.text)
    print(response.status_code)
    return "success!"


if __name__ == "__main__":
    #data = xlrd.open_workbook("D:\WORK\项目\党政项目\基于知识图谱的智能决策\数据\感知中心导出数据\HTTP木马检测-HTTP木马.xls")
    #table = data.sheet_by_index(0)
    #print(table.nrows)
    #name=table.cell(10,2).value
    #print(name)
    #tmp_oo = table.col_values(0)
    #print(tmp_oo)
    #result = get_triple(table, "entity", 2, "", "relationship", "definedBy", "", "entity", 16, "")
    #result11 = get_triple(table, "entity", 2, "", "relationship", "type", "rdf", "Ontology", "文件", "")
    #result6 = get_triple(table, "entity", 0, "", "relationship", "捕获", "", "entity", 2, "", {"捕获时间":1, "入库时间":21})
    #get_owl()
    #get_all()
    # add_node()
    # get_repository()
    del_all()
    data = generate_data()
    print(data)
    add_nodes(data)

    #get_all()
    # add_node()

    # get_all()
    # call(data,url)
