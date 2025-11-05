#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nginx IP监控工具
持续监控nginx日志，根据配置的阈值自动将违规IP加入黑名单
"""

import re
import yaml
import time
import json
import logging
import requests
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path 

# 全局日志配置函数
def setup_logging(config):
    """设置日志配置"""
    log_level_str = config.get('log_level', 'DEBUG').upper()
    log_file = config.get('log_file', 'nginx_monitor.log')
    
    # 将字符串日志级别转换为logging常量
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    log_level = log_level_map.get(log_level_str, logging.DEBUG)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ],
        force=True  # 强制重新配置日志
    )

logger = logging.getLogger(__name__)


class NginxLogMonitor:
    """Nginx日志监控和IP封禁类"""
    
    def __init__(self, config_path="config.yaml", log_level_override=None):
        """初始化配置"""
        self.config = None
        self.config_path = config_path
        # 先加载配置以获得日志设置
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)
        
        # 如果有日志级别覆盖，应用到配置中
        if log_level_override:
            self.config['log_level'] = log_level_override
        
        # 设置日志
        setup_logging(self.config)
        
        self.ip_access_records = defaultdict(lambda: {
            'access_records': [],
            'first_access': None,
            'last_access': None,
            'location': None
        })
        self.blacklist_ips = set()
        self.whitelist_ips = set()
        self.blocked_ips_info = {}  # 存储所有被封禁IP的详细信息
        self.current_period_blocked = []  # 存储本周期新增的封禁IP
        self.ip_interface_stats = defaultdict(lambda: defaultdict(int))  # 存储IP+接口的访问统计
        self.total_lines_read = 0  # 存储已读取的总行数
        self.last_report_date = None  # 记录上次发送报告的日期
        
        self.load_config()
        self.load_whitelist()
        self.load_blacklist()
        self.load_blocked_ips_info()
        self.load_ip_interface_stats()
        logger.info(f"[初始化] 配置已加载，监控路径: {self.config['monitor_paths']}")
        logger.info(f"[初始化] 白名单IP数量: {len(self.whitelist_ips)}")
        logger.info(f"[初始化] 已有黑名单IP数量: {len(self.blacklist_ips)}")
        logger.debug(f"[初始化] 白名单IP列表: {self.whitelist_ips}")
        logger.debug(f"[初始化] 已有黑名单IP列表: {self.blacklist_ips}")
    
    def load_config(self):
        """从config.yaml读取配置"""
        logger.info(f"正在加载配置文件: {self.config_path}")
        logger.debug(f"配置文件内容: {self.config}")
        
        # 验证必填配置项
        required_keys = ['nginx_log_path', 'nginx_log_format', 'monitor_paths', 
                         'threshold', 'threshold_duration', 'blacklist_file', 'whitelist_file', 'check_interval']
        for key in required_keys:
            if key not in self.config:
                logger.error(f"配置文件缺少必需的配置项: {key}")
                raise ValueError(f"配置文件缺少必需的配置项: {key}")
        
        # 设置可选的持久化文件路径（默认值）
        if 'blocked_ips_info_file' not in self.config:
            self.config['blocked_ips_info_file'] = 'blocked_ips_info.json'
        if 'ip_interface_stats_file' not in self.config:
            self.config['ip_interface_stats_file'] = 'ip_interface_stats.json'
        
        # 验证 threshold_duration 是正整数
        if not isinstance(self.config['threshold_duration'], int) or self.config['threshold_duration'] <= 0:
            logger.error(f"threshold_duration 必须是正整数，当前值: {self.config['threshold_duration']}")
            raise ValueError("threshold_duration 必须是正整数")
        
        logger.info("配置文件验证通过")
    
    def load_whitelist(self):
        """从whitelist.txt读取IP白名单"""
        whitelist_path = self.config['whitelist_file']
        logger.info(f"正在加载白名单文件: {whitelist_path}")
        if Path(whitelist_path).exists():
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.whitelist_ips.add(ip)
                        logger.debug(f"加载白名单IP: {ip}")
        else:
            logger.warning(f"白名单文件不存在: {whitelist_path}")
    
    def load_blacklist(self):
        """加载已有黑名单，支持绝对路径和手动写入的IP"""
        blacklist_path = self.config['blacklist_file']
        logger.info(f"正在加载黑名单文件: {blacklist_path}")
        if Path(blacklist_path).exists():
            with open(blacklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('deny ') and line.endswith(';'):
                        ip = line[5:-1].strip()
                        if ip:
                            self.blacklist_ips.add(ip)
                            logger.debug(f"加载黑名单IP: {ip}")
        else:
            logger.warning(f"黑名单文件不存在，将创建新文件: {blacklist_path}")
    
    def load_blocked_ips_info(self):
        """加载被封禁IP的详细信息"""
        info_file = self.config['blocked_ips_info_file']
        logger.info(f"正在加载封禁信息文件: {info_file}")
        if Path(info_file).exists():
            try:
                with open(info_file, 'r', encoding='utf-8') as f:
                    self.blocked_ips_info = json.load(f)
                logger.info(f"已加载 {len(self.blocked_ips_info)} 条封禁记录")
            except Exception as e:
                logger.error(f"加载封禁信息失败: {e}")
                self.blocked_ips_info = {}
        else:
            logger.info("封禁信息文件不存在，创建新的记录")
            self.blocked_ips_info = {}
            self.save_blocked_ips_info()
    
    def save_blocked_ips_info(self):
        """保存被封禁IP的详细信息"""
        info_file = self.config['blocked_ips_info_file']
        try:
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(self.blocked_ips_info, f, ensure_ascii=False, indent=2)
            logger.debug(f"封禁信息已保存到: {info_file}")
        except Exception as e:
            logger.error(f"保存封禁信息失败: {e}")
    
    def load_ip_interface_stats(self):
        """加载IP+接口的访问统计"""
        stats_file = self.config['ip_interface_stats_file']
        logger.info(f"正在加载访问统计文件: {stats_file}")
        if Path(stats_file).exists():
            try:
                with open(stats_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 将字典转换为 defaultdict(lambda: defaultdict(int))
                    for ip, paths in data.items():
                        for path, count in paths.items():
                            self.ip_interface_stats[ip][path] = count
                logger.info(f"已加载访问统计记录")
            except Exception as e:
                logger.error(f"加载访问统计失败: {e}")
                self.ip_interface_stats = defaultdict(lambda: defaultdict(int))
        else:
            logger.info("访问统计文件不存在，创建新的记录")
            self.save_ip_interface_stats()
    
    def save_ip_interface_stats(self):
        """保存IP+接口的访问统计"""
        stats_file = self.config['ip_interface_stats_file']
        try:
            # 将 defaultdict 转换为普通字典以便序列化
            data = {ip: dict(paths) for ip, paths in self.ip_interface_stats.items()}
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"访问统计已保存到: {stats_file}")
        except Exception as e:
            logger.error(f"保存访问统计失败: {e}")
    
    def load_log_position(self):
        """从config.yaml加载日志文件读取行数"""
        lines_read = self.config.get('last_position', 0)  # 现在记录的是行数
        log_file = self.config.get('nginx_log_path', '')
        if lines_read > 0:
            logger.info(f"从配置文件加载日志行数: {lines_read} 行 (文件: {log_file})")
            self.total_lines_read = lines_read
        else:
            logger.info("配置文件未设置日志位置，从文件开头开始读取")
        
        # 验证位置是否超过文件实际行数
        if log_file and Path(log_file).exists():
            actual_lines = self.get_file_line_count(log_file)
            if self.total_lines_read >= actual_lines and actual_lines > 0:
                logger.warning(f"配置中的日志位置 {self.total_lines_read} 超过文件行数 {actual_lines}，重置为0")
                self.total_lines_read = 0
    
    def get_file_line_count(self, file_path):
        """统计文件总行数"""
        try:
            if not Path(file_path).exists():
                return 0
            with open(file_path, 'r', encoding='utf-8') as f:
                return sum(1 for _ in f)
        except Exception as e:
            logger.error(f"统计文件行数失败 {file_path}: {e}")
            return 0
    
    def save_log_position(self, position):
        """保存日志文件读取行数到config.yaml（保持文件结构不变）"""
        try:
            # 不接收position参数，直接使用total_lines_read
            # 读取原始配置文件内容
            with open(self.config_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 更新配置内存中的数据（只保存行数，不保存字节数）
            self.config['last_position'] = self.total_lines_read
            
            # 使用正则表达式替换 last_position 的值，保持其他内容不变
            import re
            pattern = r'^(last_position:\s*)\d+(\s*)$'
            replacement = f'\\g<1>{self.total_lines_read}\\g<2>'
            new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            
            # 如果找不到 last_position 字段，在文件开头添加
            if new_content == content and 'last_position' not in content:
                lines = content.split('\n')
                # 在 nginx_log_format 行后插入
                for i, line in enumerate(lines):
                    if 'nginx_log_format:' in line:
                        lines.insert(i + 1, f'last_position: {self.total_lines_read}')
                        break
                new_content = '\n'.join(lines)
            
            # 写入配置文件
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            logger.info(f"日志行数已保存到配置文件: {self.total_lines_read} 行")
        except Exception as e:
            logger.error(f"保存日志位置失败: {e}")
    
    def get_ip_location(self, ip):
        """获取IP归属地"""
        logger.debug(f"正在查询IP归属地: {ip}")
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country', '')
                    region = data.get('regionName', '')
                    city = data.get('city', '')
                    location = f"{country}-{region}-{city}"
                    logger.debug(f"IP归属地查询成功: {ip} -> {location}")
                    return location
            logger.warning(f"IP归属地查询失败: {ip}")
            return "未知"
        except Exception as e:
            logger.error(f"获取IP归属地失败 {ip}: {e}")
            return "未知"
    
    def parse_log_line(self, line):
        """解析nginx日志行，返回(ip, path, timestamp)或None"""
        nginx_format = self.config['nginx_log_format']
        
        if nginx_format == "custom":
            # 自定义格式正则
            pattern = r'^(\S+) - \S+ \[(.*?)\] "(.+?)" (\d+) \d+ ".*?" ".*?" Host: ".*?" Request_URI: "(.+?)" Domain: ".*?" Headers: ".*?" ".*?"'
            match = re.match(pattern, line)
            if match:
                ip = match.group(1)
                timestamp_str = match.group(2)
                path = match.group(5)
                return (ip, path, timestamp_str)
        elif nginx_format == "combined":
            # combined格式正则
            pattern = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.*?) HTTP.*?" (\d+)'
            match = re.match(pattern, line)
            if match:
                ip = match.group(1)
                timestamp_str = match.group(2)
                path = match.group(4)
                return (ip, path, timestamp_str)
        
        return None
    
    def track_ip_access(self, ip, path, timestamp):
        """记录IP访问并更新时间"""
        # 更新IP+接口统计（统计所有IP，包括白名单和封禁IP）
        self.ip_interface_stats[ip][path] += 1
        
        # 检查是否为白名单IP
        if ip in self.whitelist_ips:
            logger.debug(f"IP {ip} 在白名单中，跳过监控但继续统计访问次数")
            return
        
        # 检查是否为已封禁IP
        if ip in self.blacklist_ips:
            logger.debug(f"IP {ip} 已在黑名单中，跳过监控但继续统计访问次数")
            return
        
        # 记录访问（用于监控阈值判断）
        current_time = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")
        self.ip_access_records[ip]['access_records'].append({
            'path': path,
            'timestamp': current_time
        })
        
        # 更新首次和最后访问时间
        if self.ip_access_records[ip]['first_access'] is None:
            self.ip_access_records[ip]['first_access'] = current_time
            logger.debug(f"首次记录IP访问: {ip} -> {path}")
        self.ip_access_records[ip]['last_access'] = current_time
        
        # 记录访问计数
        total_count = len(self.ip_access_records[ip]['access_records'])
        logger.debug(f"IP {ip} 访问路径 {path}，总访问次数: {total_count}")
    
    def filter_recent_accesses(self, ip):
        """过滤时间窗口内的访问记录"""
        current_time = datetime.now()
        threshold_duration = self.config['threshold_duration']
        access_records = self.ip_access_records[ip]['access_records']
        
        # 计算时间窗口的起始时间
        time_window_start = current_time - timedelta(seconds=threshold_duration)
        
        # 过滤时间窗口内的记录
        recent_records = [
            record for record in access_records 
            if record['timestamp'] > time_window_start
        ]
        
        if not recent_records:
            logger.debug(f"IP {ip} 没有访问记录")
            return [], None, None
        
        # 获取时间窗口内的首次和最后访问时间
        first_access = min(record['timestamp'] for record in recent_records)
        last_access = max(record['timestamp'] for record in recent_records)
        logger.debug(f"总访问次数: {len(recent_records)} 时间窗口内的首次访问: {first_access.strftime('%Y-%m-%d %H:%M:%S')}, 最后访问: {last_access.strftime('%Y-%m-%d %H:%M:%S')}")
        return recent_records, first_access, last_access
    
    def calculate_duration_from_records(self, first_access, last_access):
        """计算访问持续时间（基于提供的访问时间）"""
        if first_access and last_access:
            duration = (last_access - first_access).total_seconds()
            return int(duration)
        return 0
    
    def check_threshold(self, ip, current_path=None):
        """检查IP访问次数是否超过阈值（基于时间窗口）"""
        # 获取时间窗口内的访问记录
        recent_records, first_access, last_access = self.filter_recent_accesses(ip)
        # 统计时间窗口内的访问次数
        access_count = len(recent_records)
        threshold = self.config['threshold']
        total_records = len(self.ip_access_records[ip]['access_records'])
        duration_window = self.config['threshold_duration']
        
        # 达到阈值时输出详细信息
        if access_count >= threshold:
            # 计算时间窗口信息
            log_warning = f"IP {ip} 达到阈值！时间窗口内: {access_count}/{threshold} 次"
            if first_access and last_access:
                time_span = (last_access - first_access).total_seconds()
                log_warning += f" (首次: {first_access.strftime('%H:%M:%S')}, 最后: {last_access.strftime('%H:%M:%S')}, 时间跨度: {int(time_span)}秒)"
            log_warning += f" (总记录: {total_records}, 窗口: {int(duration_window/3600)}小时)"
            if current_path:
                log_warning += f", 触发路径: {current_path}"
            logger.warning(log_warning)
            return True
        elif access_count >= threshold * 0.5:  # 达到阈值的50%时才输出提示日志
            # 只在接近阈值时输出详细信息
            if first_access and last_access:
                time_span = (last_access - first_access).total_seconds()
                logger.info(f"IP {ip} 接近阈值: 时间窗口内 {access_count}/{threshold} 次 (时间跨度: {int(time_span)}秒, 总记录: {total_records})")
        return False
    
    def add_to_blacklist(self, ip, count=None, duration=0, blocked_path=None):
        """将IP添加到黑名单文件，避免重复写入"""
        blacklist_path = self.config['blacklist_file']
        
        # 检查IP是否已经在黑名单中
        if ip in self.blacklist_ips:
            logger.info(f"IP {ip} 已在黑名单中，跳过")
            return
        
        logger.info(f"正在将IP {ip} 添加到黑名单文件: {blacklist_path}")
        
        # 确保目录存在
        Path(blacklist_path).parent.mkdir(parents=True, exist_ok=True)
        
        # 追加到黑名单文件
        with open(blacklist_path, 'a', encoding='utf-8') as f:
            f.write(f"deny {ip};\n")
        
        # 添加到内存中的黑名单集合
        self.blacklist_ips.add(ip)
        logger.warning(f"IP {ip} 已成功添加到黑名单！")
        
        # 记录封禁信息
        if count is not None and blocked_path:
            block_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            location = self.ip_access_records[ip]['location'] or "未知"
            self.blocked_ips_info[ip] = {
                "blocked_time": block_time,
                "count": count,
                "duration": duration,
                "blocked_path": blocked_path,
                "location": location
            }
            self.current_period_blocked.append(ip)
            self.save_blocked_ips_info()
    
    def send_wechat_notification(self, ip, path, count, duration):
        """发送企业微信通知"""
        if 'wechat_webhook_url' not in self.config or not self.config['wechat_webhook_url']:
            logger.debug("未配置企业微信webhook URL，跳过通知")
            return
        
        location = self.ip_access_records[ip]['location'] or "未知"
        block_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 构建markdown_v2消息内容
        content = f"# Nginx IP封禁通知\n\n**IP地址：** `{ip}`\n**归属地：** {location}\n**命中路径：** `{path}`\n**阈值次数：** {count}\n**封禁时间：** {block_time}\n**触发时长：** {duration}秒"
        # 构建消息
        message = {
            "msgtype": "markdown_v2",
            "markdown_v2": {
                "content": content
            }
        }
        
        logger.info(f"正在发送企业微信通知: {ip}")
        logger.debug(f"通知内容: {json.dumps(message, ensure_ascii=False)}")
        
        try:
            response = requests.post(
                self.config['wechat_webhook_url'],
                json=message,
                timeout=5
            )
            if response.status_code == 200:
                logger.info(f"企业微信通知已成功发送: {ip}")
            else:
                logger.error(f"企业微信通知发送失败: {response.text}")
        except Exception as e:
            logger.error(f"企业微信通知发送异常: {e}")
    
    def is_ip_blocked(self, ip):
        """检查IP是否已经在黑名单中"""
        return ip in self.blacklist_ips
    
    def generate_daily_report_markdown(self):
        """生成每日报告markdown内容"""
        if not hasattr(self, 'last_statistics') or not self.last_statistics:
            return ""
        
        stats = self.last_statistics
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        content = f"# Nginx IP监控每日统计报告\n\n"
        content += f"**报告时间：** {report_time}\n\n"
        content += f"## 累计统计\n\n"
        content += f"**累计总封禁IP数量：** {stats['total_blocked_count']}\n\n"
        content += f"**累计总访问次数：** {stats['total_accesses']}\n\n"
        
        content += f"## 累计访问次数>=10的前20个IP+接口组合\n\n"
        if stats['top_20_combinations']:
            content += "| 序号 | IP地址 | 接口路径 | 访问次数 |\n"
            content += "|------|--------|----------|----------|\n"
            for idx, (ip, path, count) in enumerate(stats['top_20_combinations'], 1):
                content += f"| {idx} | `{ip}` | `{path}` | {count} |\n"
        else:
            content += "无\n"
        
        content += f"\n## 黑名单IP列表\n\n"
        if stats['blacklist_ips']:
            content += "```\n"
            content += ", ".join(stats['blacklist_ips'])
            content += "\n```\n"
        else:
            content += "无\n"
        
        content += f"\n## 白名单IP列表\n\n"
        if stats['whitelist_ips']:
            content += "```\n"
            content += ", ".join(stats['whitelist_ips'])
            content += "\n```\n"
        else:
            content += "无\n"
        
        return content
    
    def send_daily_report(self):
        """发送每日报告到企业微信"""
        if 'wechat_webhook_url' not in self.config or not self.config['wechat_webhook_url']:
            logger.debug("未配置企业微信webhook URL，跳过每日报告")
            return
        
        content = self.generate_daily_report_markdown()
        if not content:
            logger.warning("统计结果为空，跳过每日报告发送")
            return
        
        # 构建企业微信消息
        message = {
            "msgtype": "markdown_v2",
            "markdown_v2": {
                "content": content
            }
        }
        
        logger.info("正在发送每日统计报告到企业微信")
        logger.debug(f"报告内容: {json.dumps(message, ensure_ascii=False)}")
        
        try:
            response = requests.post(
                self.config['wechat_webhook_url'],
                json=message,
                timeout=10
            )
            if response.status_code == 200:
                logger.info("每日统计报告已成功发送到企业微信")
            else:
                logger.error(f"每日统计报告发送失败: {response.text}")
        except Exception as e:
            logger.error(f"每日统计报告发送异常: {e}")
    
    def log_period_statistics(self, processed_count, new_lines):
        """输出周期统计信息"""
        # 保存统计信息
        self.save_ip_interface_stats()
        # 保存日志读取位置（只保存行数）
        self.save_log_position(0)
        
        # 统计本周期访问的IP（从新日志中提取）
        period_ips = set()
        for line in new_lines:
            parsed = self.parse_log_line(line.strip())
            if parsed:
                ip, _, _ = parsed
                period_ips.add(ip)
        
        # 总访问次数统计
        total_accesses = sum(sum(paths.values()) for paths in self.ip_interface_stats.values())
        
        # 计算累计访问次数>=10的前20个IP+接口组合
        all_combinations = []
        for ip, paths in self.ip_interface_stats.items():
            for path, count in paths.items():
                if count >= 10:  # 只收集访问次数>=10的
                    all_combinations.append((ip, path, count))
        all_combinations.sort(key=lambda x: x[2], reverse=True)
        top_20_combinations = all_combinations[:20]
        
        # 保存统计结果到实例变量
        self.last_statistics = {
            'processed_count': processed_count,
            'total_accesses': total_accesses,
            'total_blocked_count': len(self.blocked_ips_info),
            'top_20_combinations': top_20_combinations,
            'blacklist_ips': sorted(list(self.blacklist_ips)),
            'whitelist_ips': sorted(list(self.whitelist_ips))
        }
        
        logger.info("=" * 80)
        logger.info(f"[周期统计] 处理日志行数: {processed_count}")
        logger.info(f"[周期统计] 本周期活跃IP数量: {len(period_ips)}")
        logger.info(f"[周期统计] 累计总访问次数: {total_accesses}")
        
        # 统计本期新增封禁
        new_blocked_count = len(self.current_period_blocked)
        total_blocked_count = len(self.blocked_ips_info)
        logger.info(f"[封禁统计] 本周期新增封禁: {new_blocked_count} 个")
        logger.info(f"[封禁统计] 累计总封禁IP: {total_blocked_count} 个")
        
        # 输出本周期新增封禁的IP列表
        if self.current_period_blocked:
            logger.info(f"[周期封禁] 本周期封禁的IP: {', '.join(self.current_period_blocked)}")
        
        # 输出访问次数在10以上的IP+接口组合
        all_combinations = []
        for ip, paths in self.ip_interface_stats.items():
            for path, count in paths.items():
                if count >= 10:  # 只收集访问次数>=10的
                    all_combinations.append((ip, path, count))
        all_combinations.sort(key=lambda x: x[2], reverse=True)
        
        # 输出前50个
        top_50 = all_combinations[:50]
        logger.info(f"[访问统计] 累计访问次数>=10的IP+接口组合 (共{len(all_combinations)}个，显示前50个):")
        if top_50:
            for idx, (ip, path, count) in enumerate(top_50, 1):
                logger.info(f"  {idx}. IP: {ip}, 接口: {path}, 访问次数: {count}")
        else:
            logger.info("  无")
        
        # 输出封禁IP的详细信息
        if self.blocked_ips_info:
            logger.info(f"[封禁详情] 所有被封禁IP的访问统计:")
            for blocked_ip, info in self.blocked_ips_info.items():
                count = info.get('count', 0)
                duration = info.get('duration', 0)
                blocked_path = info.get('blocked_path', '未知')
                location = info.get('location', '未知')
                blocked_time = info.get('blocked_time', '未知')
                
                # 计算平均访问间隔
                avg_interval = "未知"
                if count > 0 and duration > 0:
                    avg_interval = f"{duration / count:.2f}"
                
                # 统计该IP访问的所有接口
                ip_paths = self.ip_interface_stats.get(blocked_ip, {})
                total_access_count = sum(ip_paths.values()) if ip_paths else 0
                
                logger.info(f"  封禁IP: {blocked_ip}")
                logger.info(f"    - 归属地: {location}")
                logger.info(f"    - 封禁时间: {blocked_time}")
                logger.info(f"    - 触发路径: {blocked_path}")
                logger.info(f"    - 时间窗口内访问次数: {count}")
                logger.info(f"    - 平均访问间隔: {avg_interval} 秒/次")
                logger.info(f"    - 总访问次数: {total_access_count}")
                if ip_paths:
                    logger.info(f"    - 访问的接口: {', '.join([f'{p}({c}次)' for p, c in sorted(ip_paths.items(), key=lambda x: x[1], reverse=True)])}")
        
        logger.info("=" * 80)
        
        # 清空本周期封禁记录
        self.current_period_blocked = []
    
    def monitor_log(self):
        """持续监控日志的主循环"""
        log_path = self.config['nginx_log_path']
        check_interval = self.config['check_interval']
        
        logger.info(f"开始监控日志文件: {log_path}")
        
        # 加载日志文件最后读取行数
        self.load_log_position()
        
        if Path(log_path).exists():
            file_size = Path(log_path).stat().st_size
            logger.debug(f"日志文件初始大小: {file_size} 字节 log_path: {log_path}")
        
        loop_count = 0
        while True:
            try:
                loop_count += 1
                logger.debug(f"监控循环 #{loop_count}")
                
                # 检测日志文件轮转：检查读取位置是否超过文件实际行数
                actual_lines = self.get_file_line_count(log_path)
                logger.info(f"日志文件总行数: {actual_lines}, 已读取行数: {self.total_lines_read}")
                if self.total_lines_read >= actual_lines and actual_lines > 0:
                    # 记录清理前的IP数量（用于日志）
                    ip_count_before = len(self.ip_access_records)
                    logger.warning(f"日志位置 {self.total_lines_read} 超过文件行数 {actual_lines}，检测到日志轮转，重置读取位置为0并清理访问记录")
                    self.total_lines_read = 0
                    # 清理所有IP的访问记录，避免旧时间戳干扰判断
                    self.ip_access_records.clear()
                    logger.info(f"已清理所有IP访问记录，共清理 {ip_count_before} 个IP的记录")
                logger.debug(f"日志文件总行数: {actual_lines}, 已读取行数: {self.total_lines_read}")
                
                # 读取新增的日志内容（从已读取的行数之后开始）
                with open(log_path, 'r', encoding='utf-8') as f:
                    # 跳过已读取的行数
                    for i in range(self.total_lines_read):
                        f.readline()
                    # 读取剩余的所有新行
                    new_lines = f.readlines()
                    self.total_lines_read += len(new_lines)  # 更新已读取行数
                if new_lines:
                    logger.debug(f"读取到 {len(new_lines)} 条新日志")
                # 处理新增的日志行
                processed_count = 0
                for line in new_lines:
                    parsed = self.parse_log_line(line.strip())
                    logger.debug(f"解析日志行: {parsed}")
                    if parsed:
                        ip, path, timestamp = parsed
                        self.track_ip_access(ip, path, timestamp)
                        processed_count += 1
                        
                        if path not in self.config['monitor_paths']:
                            logger.debug(f"路径 {path} 不在监控列表中，跳过")
                            continue
                        # 检查是否超过阈值（基于时间窗口）
                        if self.check_threshold(ip, current_path=path) and not self.is_ip_blocked(ip):
                            logger.warning(f"IP {ip} 触发封禁条件！")
                            # 获取时间窗口内的记录
                            recent_records, first_access, last_access = self.filter_recent_accesses(ip)
                            count = len(recent_records)
                            duration = self.calculate_duration_from_records(first_access, last_access)
                            
                            # 只在触发封禁时获取IP归属地
                            if self.ip_access_records[ip]['location'] is None:
                                logger.info(f"正在获取IP归属地: {ip}")
                                self.ip_access_records[ip]['location'] = self.get_ip_location(ip)
                            
                            # 获取访问路径（取最后一个）
                            access_paths = [record['path'] for record in recent_records]
                            blocked_path = access_paths[-1] if access_paths else path
                            
                            logger.info(f"封禁详情 - IP: {ip}, 路径: {blocked_path}, 次数: {count}, 时长: {duration}秒")
                            
                            # 添加到黑名单
                            self.add_to_blacklist(ip, count=count, duration=duration, blocked_path=blocked_path)
                            
                            # 发送通知（使用时间窗口内的数据）
                            self.send_wechat_notification(ip, blocked_path, count, duration)
                
                if processed_count > 0:
                    logger.info(f"本周期处理了 {processed_count} 条日志")
                
                # 输出周期统计（保存日志位置）
                self.log_period_statistics(processed_count, new_lines)
                
                # 检查是否需要发送每日报告（每天早上8点）
                current_time = datetime.now()
                current_date = current_time.date()
                current_hour = current_time.hour
                
                if current_hour == 8 and self.last_report_date != current_date:
                    self.send_daily_report()
                    self.last_report_date = current_date
                    logger.info(f"已发送每日统计报告: {current_date}")
                
                time.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"监控异常: {e}", exc_info=True)
                # 保存数据以防异常
                try:
                    self.save_ip_interface_stats()
                    self.save_blocked_ips_info()
                    self.save_log_position(0)
                except:
                    pass
                time.sleep(check_interval)
    
    def run(self):
        """启动监控程序"""
        logger.info("="*60)
        logger.info("Nginx IP监控工具启动")
        logger.info("="*60)
        logger.info(f"监控路径: {self.config['monitor_paths']}")
        logger.info(f"阈值: {self.config['threshold']}次")
        logger.info(f"时间窗口: {self.config['threshold_duration']}秒")
        logger.info(f"检查间隔: {self.config['check_interval']}秒")
        logger.info(f"日志文件: {self.config['nginx_log_path']}")
        logger.info(f"黑名单文件: {self.config['blacklist_file']}")
        logger.info("="*60)
        
        try:
            self.monitor_log()
        except KeyboardInterrupt:
            logger.info("\n监控程序已停止（用户中断）")
            # 保存数据
            self.save_ip_interface_stats()
            self.save_blocked_ips_info()
            self.save_log_position(0)
        except Exception as e:
            logger.error(f"程序异常: {e}", exc_info=True)
            # 保存数据
            self.save_ip_interface_stats()
            self.save_blocked_ips_info()
            self.save_log_position(0)


def main():
    """主函数"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Nginx IP监控工具')
    parser.add_argument('config', nargs='?', default='config.yaml', help='配置文件路径（默认为config.yaml）')
    parser.add_argument('--log-level', '-l', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='日志级别（覆盖配置文件中的设置）')
    parser.add_argument('--log-file', '-f', help='日志文件路径（覆盖配置文件中的设置）')
    
    args = parser.parse_args()
    
    # 传递日志级别覆盖到初始化
    monitor = NginxLogMonitor(args.config, log_level_override=args.log_level)
    monitor.run()


if __name__ == "__main__":
    main()
    
