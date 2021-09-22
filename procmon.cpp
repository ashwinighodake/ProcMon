#include<iostream>
#include<sys/types.h>
#include<sys/stat.h>
#include<stat.h>
#include<windows.h>
#include<tlhelp32.h>
#include<stdio.h>
#include<io.h>

using namespace std;

typedef struct LogFile
{
    char ProcessName[100];
    unsigned int pid;
    unsigned int ppid;
    unsigned int thread_cnt;
}LOGFILE;

class ThreadInfo
{
    DWORD PID;
    HANDLE hThreadSnap;
    THREADENTRY32 te32;

    public:
    ThreadInfo();
    BOOL ThreadsDisplay();

};
ThreadInfo::ThreadInfo(DWORD no)
{
    PID=no;
    hThreadSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,PID);

    if(hThreadSnap == INVALID_HANDLE_VALUE)
    {
        cout<<"Unable to create the snapshot of current thread pool"<<endl;
        return;
    }
    te32.dwSize=sizeof(THREADENTRY32);
}
BOOL ThreadInfo::ThreadsDisplay()
{
    if(!Thread32First(hThreadSnap,&te32))
    {
        cout<<"ERROR:In getting the first thread"<<endl;
        CloseHandle(hThreadSnap);
        return FALSE;
    }
    cout<<endl<<"Thread of this Process:"<<endl;

    do
    {
        if(te32.th32OwnerProcessID == PID)
        {
            cout<<"\tThread ID:"<<te32.th32ThreadID<<endl;
        }

    }while (Thread32Next(hThreadSnap,&te32));
    CloseHandle(hTreadSnap);
    return TRUE;
}
class DLLInfo
{
    DWORD PID;
    MODULEENTRY32 me32;
    HANDLE hProcessSnap;

    public:
    DLLInfo(DWORD);
    BOOL DependentDLLDisplay();
};
DLLInfo::DLLInfo(DWORD no)
{
    PID = no;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);

    if( hProcessSnap == INVALID_HANDLE_VALUE )
    {
        cout<<"Error: Unable to create the snapshot of current thread pool"<<endl;
        return;
    }
    me32.dwSize = sizeof(MODULEENTRY32);
}
BOOL DLLInfo::DependentDLLDisplay()
{
    char arr[200];

    if (!Module32First(hProcessSnap, &me32))
    {
        cout<<"FAILED to get DLL information"<<endl;
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    cout<<"DEPENDENT DLL OF THIS PROCESS"<<endl;
    do
    {
        wcstombs_s(NULL,arr,200,me32.szModule,200);
        cout<<arr<<endl;
    }while (Module32Next(hProcessSnap, &me32));

    CloseHandle(hProcessSnap);
    return TRUE;
}

class ProcessInfo
{
    DWORD PID;
    DLLInfo *pdobj;
    ThreadInfo *ptobj;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    public:
    ProcessInfo();
    BOOL ProcessDisplay(char *);
    BOOL ProcessLog();
    BOOL ReadLog(DWORD,DWORD,DWORD,DWORD);
    BOOL ProcessSearch(char *);
    BOOL KillProcess(char *);
};
ProcessInfo::ProcessInfo()
{
    ptobj = NULL;
    pdobj = NULL;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        cout<<"Error : Unable to create the snapdhot of running processes"<<endl;
        return;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);
}
BOOL ProcessInfo::ProcessLog()
{
    char* month[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
    char FileName[50], arr[512];
    int ret = 0, fd = 0, count = 0;

    SYSTEMTIME lt;

    LOGFILE fobj;

    FILE *fp;

    GetLocalTime(&lt);
    sprintf_s(FileName,"C://MarvellousLog %02d_%02d_%02d%s.txt",lt.wHour,lt.wMinute,lt.wDay,month[lt.wMonth-1]);

    fp = fopen(FileName,"wb");
    if(fp == NULL)
    {
        cout<<"Unable to create log file"<<endl;
        return FALSE;
    }
    else
    {
        cout<<"Log file succesfully gets created as : "<<FileName<<endl;
        cout<<"Time of log file creation is->"<<lt.wHour<<":"<<lt.wMinute<<":"<<lt.wDay<<"th "<<month[lt.wMonth-1]<<endl;
    }
    if (!Process32First( hProcessSnap, &pe32))
    {
        cout<<"Error: In finding the first process."<<endl;
        CloseHandle( hProcessSnap);
        return FALSE;
    }
    do
    {
        wcstombs_s(NULL,arr,200,pe32.szExeFile,200);
        strcpy_s(fobj.ProcessName,arr);
        fobj.pid = pe32.th32ProcessID;
        fobj.ppid = pe32.th32ParentProcessID;
        fobj.thread_cnt = pe32.cntThreads;
        fwrite(&fobj,sizeof(fobj),1,fp);
     
    }while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    fclose(fp);

    return TRUE;
}
BOOL ProcessInfo::ProcessDisplay(char* option)
{
    char arr[200];

    if (!Process32First( hProcessSnap, &pe32))
    {
        cout<<"Error: In finding the first process."<<endl;
        CloseHandle( hProcessSnap);
        return FALSE;
    }
    do
    {
        cout<<endl<<"------------------------------------------------------------";
        wcstombs_s(NULL,arr,200,pe32.szExeFile,200);
        cout<<endl<<"PROCESS NAME: "<<arr;
        cout<<endl<<"PID:"<<pe32.th32ProcessID;
        cout<<endl<<"Parent PID: "<<pe32.th32ParentProcessID;
        cout<<endl<<"No of Thread: "<<pe32.cntThreads;

        if((_stricmp(option,"-a") == 0) ||(_stricmp(option,"-d") == 0)||(_stricmp(option,"-t") == 0))
        {
            if((_stricmp(option,"-t") == 0) || (_stricmp(option,"-a") == 0))
            {
                ptobj = new ThreadInfo(pe32.th32ProcessID);
                ptobj->ThreadsDisplay();
                delete ptobj;
            }
            if((_stricmp(option,"-d") == 0) || (_stricmp(option,"-a") == 0))
            {
                pdobj = new DLLInfo(pe32.th32ProcessID);
                pdobj->DependentDLLDisplay();
                delete pdobj;
            }
        }
        cout<<endl<<"------------------------------------------------------------";
    }while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return TRUE;
}
BOOL ProcessInfo::ReadLog(DWORD hr,DWORD min,DWORD date,DWORD month)
{
    char FileName[50];
    char* montharr[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
    int ret = 0, count = 0;
    LOGFILE fobj;
    FILE *fp;

    sprintf_s(FileName,"C://MarvellousLog %02d_%02d_%02d%s.txt",hr,min,date,montharr[month-1]);

    fp = fopen(FileName,"rb");
    if(fp == NULL)
    {
        cout<<"Error : Unable to open log file named as :"<<FileName<<endl;
        return FALSE;
    }
    while((ret = fread(&fobj,1,sizeof(fobj),fp)) !=0 )
    {
        cout<<"--------------------------------------------------------------"<<endl;
        cout<<"Process Name :"<<fobj.ProcessName<<endl;
        cout<<"PID of current process :"<<fobj.pid<<endl;
        cout<<"Parent process PID :"<<fobj.ppid<<endl;
        cout<<"Thread count of process :"<<fobj.thread_cnt<<endl;
    }

    return TRUE;
}
BOOL ProcessInfo::ProcessSearch(char* name)
{
    char arr[200];

    BOOL Flag = FALSE;
    if (!Process32First( hProcessSnap, &pe32))
    {
        CloseHandle( hProcessSnap);
        return FALSE;
    }

    do
    {
        wcstombs_s(NULL,arr,200,pe32.szExeFile,200);
        if(_stricmp(arr,name) == 0)
        {
            cout<<endl<<"PROCESS NAME: "<<arr;
            cout<<endl<<"PID:"<<pe32.th32ProcessID;
            cout<<endl<<"Parent PID: "<<pe32.th32ParentProcessID;
            cout<<endl<<"No of Thread: "<<pe32.cntThreads;
            Flag = TRUE;
            break;
        }
    }while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return Flag;
}
BOOL ProcessInfo::KillProcess(char *name)
{
    char arr[200];
    int pid = -1;
    BOOL bret;
    HANDLE hprocess;
   
    if (!Process32First( hProcessSnap, &pe32))
    {
        CloseHandle( hProcessSnap);
        return FALSE;
    }
    do
    { 
        wcstombs_s(NULL,arr,200,pe32.szExeFile,200);
        if(_stricmp(arr,name) == 0)
        {
            pid = pe32.th32ProcessID;
            break;
         }
    }while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    if(pid == -1)
    {
        cout<<"ERROR : There is no such process"<<endl;
        return FALSE;
    }

    hprocess = OpenProcess(PROCESS_TERMINATE,FALSE,pid);

    if(hprocess == NULL)
    {
        cout<<"ERROR : There is no access to terminate"<<endl;
        return FALSE;
    }
    bret = TerminateProcess(hprocess,0);
 
    if(bret == FALSE)
    {
        cout<<"ERROR : Unable to terminate process";
        return FALSE;
    }
}
BOOL HardwareInfo()
{
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    cout<<"OEM ID: "<<siSysInfo.dwOemId<<endl;
    cout<<"Number of processors:"<<siSysInfo.dwNumberOfProcessors<<endl;
    cout<<"Page size: "<<siSysInfo.dwPageSize<<endl;
    cout<<"Processor type: "<<siSysInfo.dwProcessorType<<endl;
    cout<<"Minimum application address:"<<siSysInfo.lpMinimumApplicationAddress<<endl;
    cout<<"Maximum application address:"<<siSysInfo.lpMaximumApplicationAddress<<endl;
    cout<<"Active processor mask: "<<siSysInfo.dwActiveProcessorMask<<endl;

    return TRUE;
}
void DisplayHelp()
{
    cout<<"Developed by Marvellous Infosystems"<<endl;
    cout<<"ps: Display all information of process"<<endl;
    cout<<"ps -t : Display all information about threads"<<endl;
    cout<<"ps -d :Display all information about DLL"<<endl;
    cout<<"cls : Cleare the contents on condole"<<endl;
    cout<<"log : Creates log of current running process on C drive"<<endl;
    cout<<"readlog : Display the information from specified log file"<<endl;
    cout<<"sysinfo : Display the current hardware configuration"<<endl;
    cout<<"search : Search and display information of specific running process"<<endl;
    cout<<"exit : Terminate Marvellous ProcMon"<<endl;
}


int main(int argc,char *argv[])
{
    BOOL bRet;
    char *ptr=NULL;
    ProcessInfo *ppobj=NULL;
    char command[4][80];
    char str[80];
    int count,min,date,month,hr;

    while(1)
    {
        fflush(stdin);
        strcpy_s(str,"");
        cout<<endl<<"Marvellous ProcMon:>";
        fgets(str,80,stdin);

        count=sscanf(str,"%s %s %s %s",command[0],command[1],command[2],command[3]);
    
        if(count==1)
        {
            if(_stricmp(command[0],"ps") == 0)
            {
               ppobj=new ProcessInfo();
               bRet=ppobj->ProcessDisplay("-a");
               if(bRet==FALSE)
               {
                   cout<<"ERROR:Unable to Display Process"<<endl;
                   delete ppobj;
               }
            }
            else if(_stricmp(command[0],"log") == 0)
            {
                ppobj=new ProcessInfo();
                bRet=ppobj->ProcessLog();
                if(bRet==FALSE)
                {
                    cout<<endl<<"ERROR:Unable to create Log file";
                }
                delete ppobj;
            }
            else if(_stricmp(command[0],"sysinfo") == 0)
            {
               bRet=HardwareInfo();
               if(bRet==FALSE)
               {
                   cout<<"ERROR:Unable to get hardware information";
               }
               cout<<"Hardware information of current System is:"<<endl;
            }
            else if(_stricmp(command[0],"readlog") == 0)
            {
                ProcessInfo *ppobj;
                ppobj=new ProcessInfo();

                cout<<"Enter Log file details as:"<<endl;
                cout<<"Hour:";
                cin>>hr;
                cout<<endl<<"Min";cin>>min;
                cout<<endl<<"Date";cin>>date;
                cout<<endl<<"Month";cin>>month;
                bRet=ppobj->ReadLog(hr,min,date,month);
                if(bRet==FALSE)
                {
                    cout<<endl<<"ERROR:Unable to read Specified log file"<<endl;
                    delete ppobj;
                }
            }
            else if(_stricmp(command[0],"clear") == 0)
            {
                system("cls");
                continue;
            }
            else if (_stricmp(command[0],"help") == 0)
            {
                DisplayHelp();
                continue;
            }
            else if (_stricmp(command[0],"exit") == 0)
            {
                cout<<endl<<"Terminating the marvellous ProcMon"<<endl;
                break;
            }
            else 
            {
                cout<<endl<<"ERROR:Command not Found!!"<<endl;
                continue;
            }
        }
        else if(count == 2)
        {
            if(_stricmp(command[0],"ps") == 0)
            {
                ppobj=new ProcessInfo();
                bRet=ppobj->ProcessDisplay(command[1]);
                if(bRet==FALSE)
                {
                    cout<<endl<<"ERROR:Unable to Display Process information";
                    delete ppobj;

                }
                continue;
            }
            else if(_stricmp(command[0],"search") == 0)
            {
                ppobj=new ProcessInfo();
                bRet=ppobj->ProcessSearch(command[1]);
                if(bRet==FALSE)
                {
                    cout<<"ERROR:There is no such Process"<<endl;
                    delete(ppobj);
                }
                continue;
            }
            else if (_stricmp(command[0],"kill") == 0)
            {
                ppobj=new ProcessInfo();
                bRet=ppobj->KillProcess(command[1]);

                if(bRet==FALSE)
                {
                    cout<<"ERROR:There is no such process"<<endl;
                }
                else
                {
                    cout<<command[1]<<"Terminated Successfully"<<endl;
                }
                delete ppobj;
                
                continue;
            }
        }
        else
        {
            cout<<endl<<"ERROR:Command not Found!!!"<<endl;
            continue;
        }
        
        
    }
    return 0;
}