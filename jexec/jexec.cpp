// surl.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <dukglue.h>
#include <json/json.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <process.h>
#include "InputBoxW.h"
#include "../Convert/Convertor.h"

//#pragma execution_character_set("utf-8")


char illegalCharset[127] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,1,1,0,1,1,1,1,1,1,1,
	0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,
	0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,1,0,1,1,0,1,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1
};

std::string readText(const char * path);
size_t writeFile(const char * path, const char * writeContent, size_t & in_outLen, int start = -1, bool bInsert = true, bool bDelTail = true);
void StringSplit(const std::string & s, const std::string & delim, std::vector<std::string>& ret);
void StringTrim(std::string& str, const std::string& trimChars = " \n\r\t");
std::string GetFileNameFromPath(const std::string & sPath);
std::string GetDirFromPath(const std::string & sPath);
bool IsFileExitst(const std::string & filePath);
std::string getValidFilePath(const std::string& path);
std::string getValidFilePathEx(const std::string& path);
std::string getPathKey(const std::string& path);
bool IsFolderExist(const std::string &strPath);

unsigned __stdcall _Execute_readAndWrite(void* arg)
{
	std::tuple<HANDLE, std::string*, HANDLE>* tpParams = (std::tuple<HANDLE, std::string*, HANDLE>*)arg;
	HANDLE hRead = std::get<0>(*tpParams);
	std::string* sPrintText = std::get<1>(*tpParams);
	HANDLE ev = std::get<2>(*tpParams);

	//读取命令行返回值
	const int BUF_LEN = 1024;
	char buff[BUF_LEN + 1];
	DWORD dwRead = 0;
	while (ReadFile(hRead, buff, BUF_LEN, &dwRead, NULL))
	{
		if (sPrintText)
		{
			buff[dwRead] = '\0';
			sPrintText->append(buff, dwRead);
		}
	}

	SetEvent(ev);

	return 0;
}

int Execute(const char* cmdLine, unsigned long& exitCode, std::string* sPrintText = NULL, unsigned long timeout = 0, bool terminateOnTimeout=true)
{
	HANDLE hRead, hWrite;
	//创建匿名管道
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return 1;
	}

	//设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite)
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	GetStartupInfoA(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_NORMAL;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;

	//启动命令行
	PROCESS_INFORMATION pi;
	if (!CreateProcessA(NULL, (char *)cmdLine, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		CloseHandle(hWrite);
		CloseHandle(hRead);
		return 2;
	}

	//立即关闭hWrite
	CloseHandle(hWrite);

	HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);

	int bRet = 0;

	unsigned int uiThreadID = 0;
	HANDLE hThreadRW = (HANDLE)_beginthreadex(NULL, 0, _Execute_readAndWrite,
		(void*)&(std::tuple<HANDLE, std::string*, HANDLE>(hRead, sPrintText, ev)), 0, &uiThreadID);

	DWORD waitRet = 0;
	if (timeout > 0)
		waitRet = WaitForSingleObject(ev, timeout);
	else
		waitRet = WaitForSingleObject(ev, INFINITE);

	switch (waitRet)
	{
	case WAIT_FAILED:
		bRet = 3;
	case WAIT_TIMEOUT:	
		if (terminateOnTimeout)
		{
			TerminateThread(hThreadRW, 1);
			TerminateProcess(pi.hProcess, 1);
			bRet = 4;
		}		
		break;
	case WAIT_OBJECT_0:
		GetExitCodeProcess(pi.hProcess, &exitCode);//获得返回值
		break;
	}

	CloseHandle(hRead);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(ev);

	return bRet;
}

std::map<std::string, int> workingDirRef;
std::string getWorkingDirDebugString();

bool js_pushWorkingDirectory(const std::string& path)
{
	std::string sPath = GL::Utf82Ansi(path.c_str());
	if (sPath.size() == 0)
		return false;

	if (!IsFolderExist(sPath))
		return false;

	std::string sPathKey = getPathKey(sPath);

	++workingDirRef[sPathKey];
	
	return true;
}

void js_popWorkingDirectory(const std::string& path)
{
	std::string sPath = GL::Utf82Ansi(path.c_str());
	if (sPath.size() == 0)
		return;

	std::string sPathKey = getPathKey(sPath);
	std::map<std::string, int>::iterator itFinder = workingDirRef.find(sPathKey);
	if (itFinder == workingDirRef.end())
		return;

	--itFinder->second;
	if (itFinder->second <= 0)
	{//清除
		workingDirRef.erase(itFinder);
	}
}

std::map<std::string, std::string> js_exec(const std::map<std::string, std::string>& params)
{
	std::map<std::string, std::string> mpRet;

	if (params.find("cmd") == params.end())
	{
		mpRet["code"] = "-1";
		mpRet["msg"] = GL::Ansi2Utf8("cmd参数为必须的");
		return mpRet;
	}

	DWORD timeout = INFINITE;
	if (params.find("timeout") != params.end())
	{
		timeout = atoi(params.at("timeout").c_str());
	}
	bool terminateOnTimeout = false;
	if (params.find("terminate_on_timeout") != params.end())
	{
		terminateOnTimeout = atoi(params.at("terminate_on_timeout").c_str()) != 0;
	}

	unsigned long exitCode = -1;
	std::string consoleText;
	std::string cmdLine = GL::Utf82Ansi(params.at("cmd").c_str());
	int nRes = Execute(cmdLine.c_str(), exitCode, &consoleText, timeout, terminateOnTimeout);
	char buff[10];
	mpRet["code"] = itoa(nRes, buff, 10);
	mpRet["exit_code"] = itoa(exitCode, buff, 10);
	mpRet["console"] = consoleText.c_str();//这里为什么不用转为utf8？

	return mpRet;
}

std::string js_execCmd(const char* cmd)
{	
	std::string sCmd = GL::Utf82Ansi(cmd);
		
	FILE* pipe = _popen(sCmd.c_str(), "r"); //打开管道，并执行命令
	if (!pipe)
		return ""; //返回0表示运行失败

	std::string sRet;
	const int BUF_LEN = 128;
	char buffer[BUF_LEN]; //定义缓冲区
	while (!feof(pipe))
	{
		memset(buffer, '\0', BUF_LEN);
		if (fgets(buffer, BUF_LEN, pipe))
		{ //将管道输出到result中
			sRet += buffer;
		}
	}
	_pclose(pipe); //关闭管道

	//std::string s1 = GL::Utf82Ansi(sRet.c_str());
	//std::string s2 = GL::Ansi2Utf8(sRet.c_str());
	return sRet.c_str();

	/*
	std::map<std::string, std::string> params;
	params["cmd"] = cmd;
	std::map<std::string, std::string> ret = js_exec(params);
	return ret["console"];*/
}

void js_print(const char* text)
{
	std::string s = GL::Utf82Ansi(text);
	std::cout << s;
}

void js_println(const char* text)
{
	std::string s = GL::Utf82Ansi(text);
	std::cout << s << std::endl;
}

void js_alert(const char* text)
{
	std::string s = GL::Utf82Ansi(text);
	MessageBoxA(NULL, s.c_str(), "jexec", MB_OK);
}

std::string js_input()
{
	std::string s;
	std::getline(std::cin, s);
	s = GL::Utf82Ansi(s.c_str());
	return s;
}

std::string js_inputBox(const char* tip, const char* defVal, const char* title)
{
	std::wstring sTip = GL::Utf82WideByte(tip);
	std::wstring sDefVal = GL::Utf82WideByte(defVal);
	std::wstring sTitle = GL::Utf82WideByte(title);
	std::wstring s = _InputBoxW(sTip.c_str(), sTitle.c_str(), sDefVal.c_str());
	return GL::WideByte2Utf8(s.c_str());
}

std::string js_readText(const char * path)
{
	std::string sPath = getValidFilePath(GL::Utf82Ansi(path));
	return readText(sPath.c_str());
}

size_t js_writeText(const char * path, const char * writeContent)
{
	std::string sPath = getValidFilePath(GL::Utf82Ansi(path));

	size_t in_outLen = strlen(writeContent);	
	return writeFile(sPath.c_str(), writeContent, in_outLen, 0, false, true);
}

size_t js_appendText(const char * path, const char * writeContent)
{
	std::string sPath = getValidFilePath(GL::Utf82Ansi(path));

	size_t in_outLen = strlen(writeContent);
	return writeFile(sPath.c_str(), writeContent, in_outLen, -1, true, false);
}

duk_ret_t js_include(duk_context * ctx)
{
	int n = duk_get_top(ctx);  /* #argc */
	if (n < 1)
		return 0;

	bool bCanReInclude = true;
	if (duk_is_boolean(ctx, n - 1))
	{
		bCanReInclude = (bool)duk_get_boolean(ctx, n - 1);
		--n;
	}

	std::string sResult;
	for (int i = 0; i < n; ++i)
	{
		const char *pFileName = duk_to_string(ctx, i);
		if (!pFileName)
			continue;

		//寻找包含目录
		std::string sFileInclude = getValidFilePathEx(GL::Utf82Ansi(pFileName));
		if (sFileInclude.empty() || sFileInclude == "")
		{
			printf("Include error (%s)\n[ %s ]\n%s\n", pFileName, "找不到文件", getWorkingDirDebugString().c_str());

			dukglue_push(ctx, false);
			return 1;
		}

		std::string sDir = GetDirFromPath(sFileInclude);
		bool bIsChangeDir = false;
		if (!sDir.empty() && sDir != "")
		{
			bIsChangeDir = js_pushWorkingDirectory(sDir);
		}
		
		//执行包含
		do
		{
			try
			{
				char buff[1024];

				std::string sIncludeName = GetFileNameFromPath(sFileInclude.c_str()).c_str();
				
				//include once
				std::string sOnceIncludeName = sIncludeName;
				//过滤掉文件名中不能组成变量的字符
				for (int c = 0; c < sOnceIncludeName.length(); ++c)
				{
					if (0 <= sOnceIncludeName[c] && sOnceIncludeName[c] < 127 && illegalCharset[sOnceIncludeName[c]])
						sOnceIncludeName[c] = '_';
				}
				std::transform(sOnceIncludeName.begin(), sOnceIncludeName.end(), sOnceIncludeName.begin(), ::toupper);
				sOnceIncludeName = "INCLUDED_" + sOnceIncludeName;
				
				if (!bCanReInclude)
				{//检测是否已经被包含过
					sprintf(buff,
						"if (typeof %s != 'undefined' && %s)"
						"	true;"
						"else"
						"	false;",
						sOnceIncludeName.c_str(), sOnceIncludeName.c_str());
					bool bIncluded = dukglue_peval<bool>(ctx, buff);
					if (bIncluded)
					{
						break;
					}
				}
				
				//include
				dukglue_peval<void>(ctx, readText(sFileInclude.c_str()).c_str());

				//mark as included
				sprintf(buff, "var %s=true;", sOnceIncludeName.c_str());
				dukglue_peval<DukValue>(ctx, buff);
			}
			catch (const std::exception& e)
			{
				printf("Include error (%s)\n[ %s ]\n", sFileInclude.c_str(), e.what());

				if (bIsChangeDir)
					js_popWorkingDirectory(sDir);

				dukglue_push(ctx, false);				
				return 1;
			}
		} while (0);

		if (bIsChangeDir)
			js_popWorkingDirectory(sDir);
	}

	dukglue_push(ctx, true);
	return 1;
}

typedef struct ParamsInfo
{
	std::string data;
	bool isFile;
} ParamsInfo;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("jexec scriptFile1 [scriptFile2 scriptFile3 ...] [-d define1 -d define2 ...]\n");
		return 1;
	}

	std::vector<ParamsInfo> vctParams;

	//初始化
	char szExePath[MAX_PATH];
	GetModuleFileNameA(NULL, szExePath, MAX_PATH);
	std::string sExeDir = GetDirFromPath(szExePath);
	js_pushWorkingDirectory(sExeDir);
	std::string sConfigFile = getValidFilePath("jexec.js");
	if (sConfigFile != "")
	{
		ParamsInfo pi;
		pi.isFile = true;
		pi.data = sConfigFile;
		vctParams.push_back(pi);
	}

	//获取参数
	for (int i = 1; i < argc; ++i)
	{
		ParamsInfo pi;
		if (strcmp(argv[i], "-d") == 0)
		{
			if (i < argc - 1)
			{
				pi.data = argv[++i];
				pi.isFile = false;
			}
		}
		else
		{
			pi.data = argv[i];
			pi.isFile = true;
		}

		vctParams.push_back(pi);
	}
		
	duk_context *ctx = NULL;
	ctx = duk_create_heap_default();
	
	std::string sCurScriptFile;
	try
	{
		//初始化js
		dukglue_register_function(ctx, &js_pushWorkingDirectory,"pushWorkingDirectory");
		dukglue_register_function(ctx, &js_execCmd,				"execCmd");
		dukglue_register_function(ctx, &js_exec,				"exec");
		dukglue_register_function(ctx, &js_print,				"print");
		dukglue_register_function(ctx, &js_println,				"println");
		dukglue_register_function(ctx, &js_alert,				"alert");
		dukglue_register_function(ctx, &js_input,				"input");
		dukglue_register_function(ctx, &js_inputBox,			"inputBox");
		dukglue_register_function(ctx, &js_readText,			"readText");
		dukglue_register_function(ctx, &js_writeText,			"writeText");
		dukglue_register_function(ctx, &js_appendText,			"appendText");
		dukglue_register_primitive_function(ctx, &js_include,	"include");

		//执行脚本
		for (int i = 0; i < vctParams.size(); ++i)
		{
			ParamsInfo& pi = vctParams[i];

			if (pi.isFile)
			{
				sCurScriptFile = getValidFilePathEx(pi.data);
				if (sCurScriptFile == "")
				{
					sCurScriptFile = getValidFilePathEx(GL::Utf82Ansi(pi.data.c_str()));
					if (sCurScriptFile == "")
					{
						throw std::exception((pi.data + " 脚本不存在。\n" + getWorkingDirDebugString()).c_str());
					}
				}

				std::string sDir = GetDirFromPath(sCurScriptFile);
				bool bIsChangeDir = false;
				if (!sDir.empty() && sDir != "")
				{
					bIsChangeDir = js_pushWorkingDirectory(sDir);
				}

				std::string sScript = readText(sCurScriptFile.c_str());
				dukglue_peval<void>(ctx, sScript.c_str());

				if (bIsChangeDir)
					js_popWorkingDirectory(sDir);
			}
			else
			{
				sCurScriptFile = pi.data;
				dukglue_peval<void>(ctx, pi.data.c_str());
			}
		}		
	}
	catch (DukErrorException ex)
	{
		std::cout << '“' << (sCurScriptFile != "" ? sCurScriptFile.c_str() : "文件") << "”出错，出错信息为：" << std::endl
			<< ex.what() << std::endl;
	}
	catch (std::exception ex)
	{
		std::cout << '“' << (sCurScriptFile != "" ? sCurScriptFile.c_str() : "文件") << "”出错，出错信息为：" << std::endl
			      << ex.what() << std::endl;
	}

	duk_destroy_heap(ctx);
    return 0;
}

size_t writeFile(const char * path, const char * writeContent, size_t & in_outLen, int start/* = -1*/, bool bInsert/* = true*/, bool bDelTail/* = true*/)
{
	if (!path)
	{
		return -1;
	}

	FILE *f = NULL;
	if ((f = fopen(path, "rb+")) == NULL)
	{
		//文件不存在，则新建一个空的
		if ((f = fopen(path, "wb")) == NULL)
		{
			return -1;
		}
		fclose(f);

		if ((f = fopen(path, "rb+")) == NULL)
			return -1;
	}

	do
	{
		int nFileSize = 0;
		if (fseek(f, 0, SEEK_END) != 0)
		{
			nFileSize = 0;
		}
		else
		{
			nFileSize = ftell(f);
		}
		if (nFileSize < 0)
		{
			break;
		}

		char* pOldStart = NULL;
		char* pOldEnd = NULL;
		if (start > -1)
		{
			if (nFileSize < start)
			{//插入处比原有的文件大，则在原文件尾到插入处空白的这些位置填充NULL
				int nSpace = start - nFileSize + 1;
				char *pSpace = new char[nSpace];
				memset(pSpace, 0, nSpace);
				fwrite(pSpace, nSpace, 1, f);
				delete[] pSpace;
			}
			else if (bInsert && (nFileSize > start))
			{//在中间插入要写的内容
			 //读取插入处到原文件结尾处的内容，以回写
				int nRead = (nFileSize - start);
				fseek(f, start, SEEK_SET);
				pOldEnd = new char[nRead];
				fread(pOldEnd, 1, nRead, f);
			}
			else if (bDelTail && (nFileSize > start) && (in_outLen < nFileSize - start))
			{//回写插入处前面的内容，而丢弃插入处后面的内容
			 //读取插入处前面的内容
				if (start > 0)
				{
					fseek(f, 0, SEEK_SET);
					pOldStart = new char[start];
					fread(pOldStart, 1, start, f);
				}

				//删除原有的文件，新建一个空的
				fclose(f);
				remove(path);
				if ((f = fopen(path, "wb")) == NULL)
				{
					return -1;
				}
				//回写插入处前面的内容，而丢弃插入处后面的内容
				if (start > 0)
					fwrite(pOldStart, 1, start, f);
			}

			if (fseek(f, start, SEEK_SET) != 0)
			{
				if (pOldEnd)
				{
					delete[] pOldEnd;
				}
				break;
			}
		}

		in_outLen = fwrite(writeContent, 1, in_outLen, f);
		if (pOldEnd)
		{
			fwrite(pOldEnd, 1, (nFileSize - start), f);
			delete[] pOldEnd;
		}

	} while (0);

	int nFileSize = 0;
	if (fseek(f, 0, SEEK_END) != 0)
	{
		nFileSize = -1;
	}
	else
	{
		nFileSize = ftell(f);
	}

	fclose(f);
	return nFileSize;
}

std::string readText(const char * path)
{
	FILE *f = NULL;
	long sz;

	if (!path)
	{
		return "";
	}

	std::string sRet;

	f = fopen(path, "rb");
	if (!f)
	{
		return "";
	}

	do
	{
		if (fseek(f, 0, SEEK_END) < 0)
		{
			break;
		}

		sz = ftell(f);
		if (sz < 0)
		{
			break;
		}

		if (fseek(f, 0, SEEK_SET) < 0)
		{
			break;
		}

		sRet.resize((size_t)sz + 1, '\0');

		if ((size_t)fread(const_cast<char*>(sRet.c_str()), 1, (size_t)sz, f) != (size_t)sz)
		{
			sRet = "";
			break;
		}
	} while (0);

	fclose(f);

	return sRet;
}

void StringSplit(const std::string & s, const std::string & delim, std::vector<std::string>& ret)
{
	size_t last = 0;
	size_t index = s.find_first_of(delim, last);
	while (index != std::string::npos)
	{
		ret.push_back(s.substr(last, index - last));
		last = index + 1;
		index = s.find_first_of(delim, last);
	}
	if (index - last > 0)
	{
		ret.push_back(s.substr(last, index - last));
	}
}

void StringTrim(std::string& str, const std::string& trimChars)
{
	if (!str.empty())
	{
		str.erase(0, str.find_first_not_of(trimChars));
		str.erase(str.find_last_not_of(trimChars) + 1);
	}
}

bool StringReplaceA(std::string & strBase, const std::string & strSrc, const std::string & strDes)
{
	bool b = false;

	std::string::size_type pos = 0;
	std::string::size_type srcLen = strSrc.size();
	std::string::size_type desLen = strDes.size();
	pos = strBase.find(strSrc, pos);
	while ((pos != std::string::npos))
	{
		strBase.replace(pos, srcLen, strDes);
		pos = strBase.find(strSrc, (pos + desLen));
		b = true;
	}

	return b;
}

std::string GetFileNameFromPath(const std::string & sPath)
{
	size_t split1 = sPath.find_last_of('/');
	size_t split2 = sPath.find_last_of('\\');
	size_t split = 0;
	if (split1 == std::string::npos)
		split = split2;
	else if (split2 == std::string::npos)
		split = split1;
	else
		split = max(split1, split2);

	if (std::string::npos == split)
		return sPath;

	return sPath.substr(split + 1).c_str();
}

std::string GetDirFromPath(const std::string & sPath)
{
	std::string path = sPath;
	char c = path[path.size() - 1];
	if (c == '\\' || c == '/')
	{
		path = path.substr(0, path.size() - 1);
	}

	size_t split1 = path.find_last_of('/');
	size_t split2 = path.find_last_of('\\');
	size_t split = 0;
	if (split1 == std::string::npos)
		split = split2;
	else if (split2 == std::string::npos)
		split = split1;
	else
		split = max(split1, split2);

	if (std::string::npos != split)
	{
		path = path.substr(0, split);
	}
	else
	{
		path = "";
	}

	return path.c_str();
}

bool IsFileExitst(const std::string & filePath)
{
	WIN32_FIND_DATAA wfd;
	bool rValue = false;
	HANDLE hFind = FindFirstFileA(filePath.c_str(), &wfd);
	if ((hFind != INVALID_HANDLE_VALUE) && !(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		rValue = true;
	}
	FindClose(hFind);
	return rValue;
}

bool IsFolderExist(const std::string &strPath)
{
	WIN32_FIND_DATAA wfd;
	bool rValue = false;
	HANDLE hFind = FindFirstFileA(strPath.c_str(), &wfd);
	if ((hFind != INVALID_HANDLE_VALUE) && (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		rValue = true;
	}
	FindClose(hFind);
	return rValue;
}

std::string getValidFilePath(const std::string& path)
{
	if (IsFileExitst(path))
		return path;

	for (std::map<std::string, int>::iterator it=workingDirRef.begin(); it!=workingDirRef.end(); ++it)
	{
		std::string newPath = it->first + path;
		if (IsFileExitst(newPath))
			return newPath;
	}
	return "";
}

std::string getValidFilePathEx(const std::string& path)
{
	std::string s = getValidFilePath(path);
	if (s == "")
		s = getValidFilePath(path + ".js");
	return s;
}

std::string getPathKey(const std::string& path)
{
	if (path.empty() || path == "")
		return "";

	std::string sPath = path;
	if (path[path.size() - 1] != '\\' && path[path.size() - 1] != '/')
		sPath += '\\';

	StringReplaceA(sPath, "/", "\\");
	std::transform(sPath.begin(), sPath.end(), sPath.begin(), ::tolower);

	return sPath;
}

std::string getWorkingDirDebugString()
{	
	std::string sRet;
	for (std::map<std::string, int>::iterator it = workingDirRef.begin(); it != workingDirRef.end(); ++it)
	{
		if (!sRet.empty())
			sRet += '\n';
		sRet += it->first;
	}
	
	return sRet;
}