import os
import requests
from datetime import datetime
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import time
from tqdm import tqdm
import gc

debug = True

def czc_read_csv(path, chunksize=100000, parse_dates=['dex_date']):
    starttime = time.perf_counter()
    chunks = []
    for chunk in tqdm(pd.read_csv(path, parse_dates=parse_dates, chunksize=chunksize)):
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)
    endtime = time.perf_counter()
    print('读取完毕，用时：', endtime - starttime)
    return df

def filter_apk(config, output_dir, csv_path='latest.csv', random_selection=False, random_sample_size=0):
    start_year_filter = config['start_year']
    end_year_filter = config['end_year']
    dex_size_limit = config['dex_size_limit']
    apk_size_limit = config['apk_size_limit']
    print('文件读取中')
    df = czc_read_csv(csv_path, parse_dates=['dex_date'])
    df.set_index('dex_date', inplace=True)
    # 筛选数据
    print('筛选 APK 中')
    filtered_df = df.loc[(df.index.year >= start_year_filter) & (df.index.year <= end_year_filter) &
                         (df['vt_detection'] == 0) & (df['dex_size'] < dex_size_limit) &
                         (df['apk_size'] < apk_size_limit)]
    # 随机抽样
    if random_selection:
        if random_sample_size < len(filtered_df):
            # 仅当随机抽样量小于数据总量时才进行抽样
            filtered_df = filtered_df.sample(n=random_sample_size)
    filtered_df.to_csv(os.path.join(output_dir, 'filtered_apks.csv'), index=False)
    del df  # 删除df释放内存
    gc.collect()  # 强制进行垃圾回收
    return filtered_df

def generate_download_link(filtered_df, out_dir, split_size=1000000):
    # 创建下载链接目录
    links_dir_name = os.path.join(out_dir, 'links')
    os.makedirs(links_dir_name, exist_ok=True)
    # 拆分下载链接并保存到多个TXT文件
    print('链接生成中')
    num_rows = filtered_df.shape[0]
    for i in range(0, num_rows, split_size):
        chunk_df = filtered_df.iloc[i:i + split_size]
        links_file = os.path.join(links_dir_name, f'links_{i // split_size + 1}.txt')
        with open(links_file, 'w') as f:
            for sha_value in chunk_df['sha256']:
                link = f"https://androzoo.uni.lu/api/download?apikey={apikey}&sha256={sha_value}\n"
                f.write(link)
    del filtered_df  # 删除filtered_df释放内存
    gc.collect()  # 强制进行垃圾回收
    return links_dir_name

def download_apk(url, download_path, pbar):
    try:
        while 1:
            response = requests.get(url, verify=True)
            if response.status_code == 200:
                apk_name = url.split('=')[-1] + '.apk'
                with open(os.path.join(download_path, apk_name), 'wb') as file:
                    file.write(response.content)
                pbar.set_postfix_str(f'已下载: {apk_name}')
                pbar.update(1)
                break
            time.sleep(1)
    except Exception as e:
        pbar.set_postfix_str(f'下载错误: {url}: {e}')
        pbar.update(1)

def download_apk_multithreaded(links_dir, output_dir, num_threads=200):
    download_dir = os.path.join(output_dir, 'apks')
    os.makedirs(download_dir, exist_ok=True)
    all_download_links = []
    for txt_file in os.listdir(links_dir):
        with open(os.path.join(links_dir, txt_file), 'r') as file:
            download_links = file.readlines()
            all_download_links.extend([link.strip() for link in download_links])
    with tqdm(total=len(all_download_links), desc='下载进度') as pbar:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(download_apk, link, download_dir, pbar) for link in all_download_links]
            for future in futures:
                future.result()

def re_download(output_dir, num_threads=1):
    links_dir = os.path.join(output_dir, 'links')
    apks_dir = os.path.join(output_dir, 'apks')
    all_links = []
    for txt_file in os.listdir(links_dir):
        with open(os.path.join(links_dir, txt_file), 'r') as file:
            download_links = file.readlines()
            all_links += [link.strip()[-64:] for link in download_links]
    all_apks = [apk[:-4] for apk in os.listdir(apks_dir)]
    failed_apk_downloads = list(set(all_links).difference(set(all_apks)))
    failed_apk_downloads_df = pd.DataFrame({'sha256': failed_apk_downloads})
    print(f'共 {len(failed_apk_downloads)} 个 APK 下载失败')
    re_download_dir = os.path.join(output_dir, datetime.now().strftime("%Y_%m_%d_%H_%M_redownload"))
    os.makedirs(re_download_dir, exist_ok=True)
    print('重新生成下载链接')
    re_download_links_dir = generate_download_link(failed_apk_downloads_df, out_dir=re_download_dir)
    print('开始重新下载')
    download_apk_multithreaded(re_download_links_dir, re_download_dir, num_threads=num_threads)

def debug_print(a):
    if debug: print(a)



