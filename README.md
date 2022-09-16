# surl
一个基于javascript的curl


GET请求用例：
命令行：surl surl_config.js test_get.js common\get.js common\log.js
参数说明：surl_config.js--初始化  test_get.js--设置参数  get.js--执行  log.js--记录日志

POST请求用例：
命令行：surl surl_config.js test_post.js common\post.js common\log.js
参数说明：surl_config.js--初始化  test_post.js--设置参数  get.js--执行  log.js--记录日志

下载文件用例：
surl surl_config.js test_download.js common\progress.js common\download.js
参数说明：surl_config.js--初始化  test_download.js--设置参数  progress.js--显示进度  download.js--执行

命令行定义参数：
surl.exe surl_config.js -d "P.url='https://www.baidu.com'" common/get.js common/dump.js
-d后面紧接着是参数的定义其实就是一句js语句

include方式：
例如：GET请求用例 中可以在一个test_get.sl文件中写：
include("surl_config.js", "test_get.js", "common\get.js", "common\log.js");
这样就不用每次都要带一大串参数了，直接执行：surl test_get.sl  即可。

例如：下载文件用例 中可以在一个test_d.sl文件中写：
include("surl_config.js");
P.url="https://www.baidu.com";
include("common\\get.js", "common\\dump.js");

