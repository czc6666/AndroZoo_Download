import AndroZoo_Download_function as AD
import os
from datetime import datetime

apikey = '输入你的api'
configs = {
    'start_year': 2014,
    'end_year': 2014,
    'dex_size_limit': 500 * 1024,
    'apk_size_limit': 1024 * 1024 * 1024
}

if __name__ == '__main__':

    output_dir = datetime.now().strftime("%Y%m%d")
    output_dir += '_' + '_'.join([str(configs[c]) for c in configs])
    AD.debug_print('生成下载目录名字')

    os.makedirs(output_dir, exist_ok=True)
    AD.debug_print('创建下载目录完成')

    df = AD.filter_apk(configs, output_dir, random_selection=True, random_sample_size=40000)
    AD.debug_print('apk过滤完成')

    links_dir = AD.generate_download_link(df, output_dir, apikey=apikey)
    AD.debug_print('下载链接txt生成完成')

    AD.debug_print('开始多线程下载')
    AD.download_apk_multithreaded(links_dir, output_dir, num_threads=200)
