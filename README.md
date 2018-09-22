# GdiLeakDetector
##Introduction
This is an easy-to-use, powerful, and efficient tool to detect and locate GDI leaks. It can be a good tool for use with Visual Studio.

## Mechanism of the tool
The tool has two parts: GdiLeakDetector.exe and GdiSpy.dll.

GdiLeakDetector.exe is a special debugger. It will launch a process in debug mode and will inject GdiSpy.dll to the debuggee. GdiSpy.dll will intercept the GDI get/create call to log the call stack and intercept the release/delete call to remove the corresponding log. If there is any leak when the debuggee exits, there may be GDI leaks. I say 'may' because the spy DLL may not be the last DLL unloaded, and some DLLs may be unloaded after it and then release the GDI resources they hold. So in theory, the wrong leak report can occur. But I don't think it's a big problem because developers can easily ignore the wrong reports.

## Acknowledgement
Thanks to StackWalker from CodeProject. I learned a lot from the code.

## class StackWalker API
I have rewritten the class to meet my needs:

```cpp
class CStackWalker
{ 
    public: 
    CStackWalker(LPCTSTR symPath); 
    ~CStackWalker(); 
    // skipFrameCount: don't get the last skipFrameCount callstack entries. 
    // maxFrameCount: get maxFrameCount callstack entries at most. 
    // if maxFrameCount == -1, 
    // get as many callstack entries as possible. 
    void GetCallStack(/*out*/vector<string>& callStacker, 
        int skipFrameCount, int maxFrameCount=10); 
    private: 
    ... 
}
```
Now you can reuse the class like this:

```cpp
//some .cpp file 
CStackWalker g_StackWalker; 
void somefunc() 
{ 
    vector<string> callStacks; 
    g_StackWalker.GetCallstack(callStacks, 1); 
    ShowCallstack(callStacks); 
} 
//other .cpp file 
extern CStackWalker g_StackWalker; 
void otherfunc() 
{ 
    vector<string> callStacks; 
    g_StackWalker.GetCallstack(callStacks, 1); 
    ShowCallstack(callStacks); 
}
```
