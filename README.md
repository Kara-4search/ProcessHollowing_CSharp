# ProcessHollowing_CSharp

Blog link: not gonna update

- Process Hollowing is a technique used by malware authors for evading endpoint detection. 
- The malware initially spawns a legitimate-looking process that is used as a container for executing malicious code. 
- The main idea is to create an executable section in the said legitimate process which in turn executes the malicious code. 
- The advantage of this technique is that when tracing back to the malicious code will lead the analysis to the legitimate process.

- Below are the steps followed while adding the Process Hollowing technique in the tool.

	- **Step 1: Create a new target process in a suspended state. This can be achieved by passing the Create_Suspended value in the dwCreationFlags parameter of CreateProcess Windows API.
	- **Step 2: Once the process is created in a suspended state we will create a new executable section. It won't be bind to any process. 
	- **Step 3: We need to locate the base address of the target process. This can be done by getting ThreadContext.
		- **Security Researchers found that the register Rdx was pointing to a memory location. 16 bytes after this location contains the address of the location of ImageBase.

	- **Step 4: Hollowing the suspended process by calling the API - ZwUnmapViewOfSection
	- **Step 5: Allocating space for the Malware Image.
	- **Step 6: Rewriting PE headers and sections into memory.
	- **Step 7: Updating the ThreadContext's ImageBase and EntryPoint.
	- **Step 8: Resume the thread with API - ResumeThread.
	
- Only tested in Win10/x64 works fine.	
- **Below are the original process and malware process's path**
```
	string OriPath = @"C:\Windows\System32\mspaint.exe";
	string MalPath = @"C:\Windows\System32\cmd.exe";
```

## Usage 
1. test the OriPath and MalPath before you run.
	![avatar](https://raw.githubusercontent.com/Kara-4search/ProjectPics/main/ProcessHollowing_Path.png)
2. Cmd show up
	![avatar](https://raw.githubusercontent.com/Kara-4search/ProjectPics/main/ProcessHollowing_CMD.png)

## TO-DO list
- Restructure Code
- PE relocation

## Update history
- NONE

# Reference link:
	1. https://www.displayfusion.com/Discussions/View/converting-c-data-types-to-c/?ID=38db6001-45e5-41a3-ab39-8004450204b3
	2. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection
	3. https://dev.to/wireless90/process-injection-process-hollowing-52m1
	4. https://blog.csdn.net/Entodie/article/details/100526765
	5. https://idiotc4t.com/code-and-dll-process-injection/setcontext-hijack-thread
	6. https://github.com/wireless90/ProcessInjector.NET/tree/main/ProcessInjector/ProcessHollowing
	7. https://3xpl01tc0d3r.blogspot.com/2019/10/process-injection-part-iii.html
	8. https://gist.github.com/affix/994d7b806a6eaa605533f46e5c27fa5e
	9. https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
	10. http://blog.sina.com.cn/s/blog_a9303fd90101bwxj.html
	11. https://docs.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	12. https://blog.csdn.net/charge_release/article/details/52224839
	13. https://docs.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	14. https://docs.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
	15. https://github.com/idiotc4t/ProcessHollow
	16. https://blog.csdn.net/weixin_43742894/article/details/105155482
	17. https://www.elastic.co/cn/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
