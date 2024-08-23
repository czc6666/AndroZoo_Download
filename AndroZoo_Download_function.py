import os
import requests
from datetime import datetime
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import time
from tqdm import tqdm
import gc
import random

debug = True


# 读取 CSV 文件并按块处理
def czc_read_csv(path, chunksize=100000, parse_dates=['dex_date']):
    debug_print(f'开始读取 CSV 文件：{path}')
    starttime = time.perf_counter()
    chunks = []
    # 使用 pandas 的 chunk 机制逐块读取大文件
    for chunk in tqdm(pd.read_csv(path, parse_dates=parse_dates, chunksize=chunksize)):
        chunks.append(chunk)
    # 合并所有块到一个 DataFrame
    df = pd.concat(chunks, ignore_index=True)
    endtime = time.perf_counter()
    debug_print(f'CSV 文件读取完毕，用时：{endtime - starttime}')
    return df


# 筛选符合条件的 APK 并生成包含 SHA256 值的 TXT 文件
def czc_filter_apk(config, output_dir, csv_path='latest.csv'):
    debug_print('开始筛选 APK')
    start_year_filter = config['start_year']
    end_year_filter = config['end_year']
    dex_size_limit = config['dex_size_limit']
    apk_size_limit = config['apk_size_limit']

    debug_print('文件读取中')
    # 读取 CSV 文件
    df = czc_read_csv(csv_path, parse_dates=['dex_date'])
    df.set_index('dex_date', inplace=True)

    # 筛选数据
    debug_print('筛选 APK 中')
    filtered_df = df.loc[(df.index.year >= start_year_filter) & (df.index.year <= end_year_filter) &
                         (df['vt_detection'] == 0) & (df['dex_size'] < dex_size_limit) &
                         (df['apk_size'] < apk_size_limit)]
    sha256_list = filtered_df['sha256'].tolist()

    # 生成文件名，包含筛选条件
    filtered_conditions = f"start_year_{start_year_filter}_end_year_{end_year_filter}_dex_size_{dex_size_limit}_apk_size_{apk_size_limit}"
    filtered_file = os.path.join(output_dir, f'筛选后apk_{filtered_conditions}.txt')
    debug_print('apk筛选完成')

    # 保存筛选结果的 SHA256 值到文件
    debug_print('保存 SHA256 到文件')
    with open(filtered_file, 'w') as f:
        for sha in sha256_list:
            f.write(sha + '\n')
    debug_print('apk筛选导出到txt完成')

    del df  # 删除 df 释放内存
    gc.collect()  # 强制进行垃圾回收
    debug_print('垃圾回收完成')

    return filtered_file


# 下载 APK 并记录已下载的文件
def czc_download_apk(apikey, filtered_file, output_dir, target_count=10000):
    debug_print('开始下载 APK')
    filtered_conditions = os.path.splitext(os.path.basename(filtered_file))[0]
    downloaded_file = os.path.join(output_dir, f'已下载apk_{filtered_conditions}.txt')

    if not os.path.exists(downloaded_file):
        open(downloaded_file, 'w').close()

    with open(filtered_file, 'r') as f:
        sha256_list = f.readlines()

    with open(downloaded_file, 'r') as f:
        downloaded_list = f.readlines()

    sha256_list = [sha.strip() for sha in sha256_list]
    downloaded_list = [sha.strip() for sha in downloaded_list]

    to_download = list(set(sha256_list) - set(downloaded_list))
    random.shuffle(to_download)

    download_dir = os.path.join(output_dir, 'apks')
    os.makedirs(download_dir, exist_ok=True)
    debug_print(f'下载目录已创建：{download_dir}')

    with tqdm(total=target_count, desc='下载进度') as pbar:
        while len(downloaded_list) < target_count and to_download:
            sha256 = to_download.pop()
            url = f"https://androzoo.uni.lu/api/download?apikey={apikey}&sha256={sha256}"
            debug_print(f'尝试下载 APK：{sha256}')
            try:
                response = requests.get(url, verify=True, timeout=10)
                if response.status_code == 200:
                    apk_name = sha256 + '.apk'
                    with open(os.path.join(download_dir, apk_name), 'wb') as file:
                        file.write(response.content)
                    downloaded_list.append(sha256)
                    with open(downloaded_file, 'a') as f:
                        f.write(sha256 + '\n')
                    pbar.update(1)
                    debug_print(f'下载成功：{sha256}')
                else:
                    debug_print(f'下载失败：{sha256}, 状态码：{response.status_code}')
            except Exception as e:
                debug_print(f'下载错误：{sha256}，错误信息：{e}')


# 多线程下载 APK 文件
def czc_download_apk_multithreaded(apikey, filtered_file, output_dir, target_count=10000, num_threads=200):
    debug_print('开始多线程下载 APK')
    filtered_conditions = os.path.splitext(os.path.basename(filtered_file))[0]
    downloaded_file = os.path.join(output_dir, f'已下载apk_{filtered_conditions}.txt')

    if not os.path.exists(downloaded_file):
        open(downloaded_file, 'w').close()

    with open(filtered_file, 'r') as f:
        sha256_list = f.readlines()

    with open(downloaded_file, 'r') as f:
        downloaded_list = f.readlines()

    sha256_list = [sha.strip() for sha in sha256_list]
    downloaded_list = [sha.strip() for sha in downloaded_list]

    to_download = list(set(sha256_list) - set(downloaded_list))
    random.shuffle(to_download)

    download_dir = os.path.join(output_dir, 'apks')
    os.makedirs(download_dir, exist_ok=True)
    debug_print(f'下载目录已创建：{download_dir}')

    def download_task(sha256, pbar):
        url = f"https://androzoo.uni.lu/api/download?apikey={apikey}&sha256={sha256}"
        debug_print(f'尝试下载 APK：{sha256}')
        try:
            response = requests.get(url, verify=True, timeout=10)
            if response.status_code == 200:
                apk_name = sha256 + '.apk'
                with open(os.path.join(download_dir, apk_name), 'wb') as file:
                    file.write(response.content)
                with open(downloaded_file, 'a') as f:
                    f.write(sha256 + '\n')
                pbar.update(1)
                debug_print(f'下载成功：{sha256}')
            else:
                debug_print(f'下载失败：{sha256}, 状态码：{response.status_code}')
        except Exception as e:
            debug_print(f'下载错误：{sha256}，错误信息：{e}')

    with tqdm(total=target_count, desc='下载进度') as pbar:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            while len(downloaded_list) < target_count and to_download:
                sha256 = to_download.pop()
                future = executor.submit(download_task, sha256, pbar)
                futures.append(future)
                downloaded_list.append(sha256)
            for future in futures:
                future.result()
    debug_print('多线程下载完成')


# 调试打印
def debug_print(message):
    if debug:
        print(message)


# 生成下载目录
def 生成下载目录(download_dir):
    output_subdir = datetime.now().strftime("%Y%m%d") + '_' + '_'.join([str(configs[c]) for c in configs])
    output_dir = os.path.join(download_dir, output_subdir)
    debug_print(f'生成下载目录名字：{output_dir}')

    os.makedirs(output_dir, exist_ok=True)
    debug_print('创建下载目录完成')

    return output_dir


if __name__ == '__main__':
    apikey = '58b1fe025f2e5ab21ebb282515415dea1eeb28985d9083c0a397e7eda08ea8f8'
    configs = {
        'start_year': 2014,
        'end_year': 2014,
        'dex_size_limit': 500 * 1024,
        'apk_size_limit': 1024 * 1024 * 1024
    }

    output_dir = 生成下载目录(download_dir='')  # 指定下载路径，例如 'D:/downloads'，如果留空则为当前目录

    filtered_file = czc_filter_apk(configs, output_dir)

    czc_download_apk_multithreaded(apikey, filtered_file, output_dir, target_count=10000, num_threads=200)
