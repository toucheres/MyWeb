
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define SERVER_IP_ADDR "0.0.0.0"	//服务器IP地址
#define SERVER_PORT 8007				//服务器端口号
#define BACKLOG 10
#define BUF_SIZE 8192
#define OK 1
#define ERROR 0
//#include <windows.h>
#include <direct.h>  // For _getcwd
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h> 
#include <time.h>
#include <WinSock2.h>
#include <threads.h>
#pragma comment(lib,"ws2_32.lib")

struct Handle_Request_Message_arg
{
	char* message;
	int length;
	struct sockaddr* clientaddr;
};

const char* Server_name = "Server: Web Server 1.0 - BooLo\r\n";
//Web服务器信息 

int Server_Socket_Init(int port);
int Handle_Request_Message(char* message, int Socket);
int Judge_URI(char* URI, int Socket);
int Send_Ifon(int Socket, const char* sendbuf, int Length);
int Error_Request_Method(int Socket);
int Inquire_File(char* URI);
int File_not_Inquire(int Socket);
int Send_File(char* URI, int Socket);
int Logo();
const char* Judge_Method(char* method, int Socket);
const char* Judge_File_Type(char* URI, const char* content_type);
const char* Get_Data(const char* cur_time);
const char* Post_Value(char* message);

int Server_Socket_Init(int port) {
	// 创建套接字 
	//WORD wVersionrequested;
	//WSADATA wsaData;
	SOCKET ServerSock;
	struct sockaddr_in ServerAddr;
	int rval;



	/* 初始化套接字 */
	ServerSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ServerSock == INVALID_SOCKET) {
		printf("Failed to create socket!\n");
		system("pause");
		exit(1);
	}
	printf("Succeed to create socket!\n");

	/* 配置服务器IP、端口信息 */
	memset(&ServerAddr, 0, sizeof(struct sockaddr));	//每一个字节都用0来填充
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(port);//htons() 接受一个无符号短整型参数（通常是端口号），并返回其转换后的网络字节序表示
	ServerAddr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDR);

	/* 绑定 */
	rval = bind(ServerSock, (SOCKADDR*)&ServerAddr, sizeof(struct sockaddr));
	if (rval == SOCKET_ERROR) {
		printf("Failed to bind stream socket!\n");
		system("pause");
		exit(1);
	}
	printf("Succeed to bind stream socket!\n");

	return ServerSock;
}



int Handle_Request_Message(char* message, int Socket) {
	//处理HTTP请求报文信息 
	int rval = 0;
	char Method[BUF_SIZE];
	char URI[BUF_SIZE];
	char Version[BUF_SIZE];

	if (sscanf(message, "%s %s %s", Method, URI, Version) != 3) {
		printf("Request line error!\n");
		return ERROR;
	} //提取"请求方法"、"URL"、"HTTP版本"三个关键要素 

	if (Judge_Method(Method, Socket) == ERROR) {
		return ERROR;
	}
	else if (Judge_Method(Method, Socket) == "POST") {
		Post_Value(message);
	} //判断处理"请求方法" 

	// 如果URI是根目录，则将其重定向到 /index.html
	if (strcmp(URI, "/") == 0) {
		strcpy(URI, "/index.html");
	}

	if (Judge_URI(URI, Socket) == ERROR) {
		return ERROR;
	} //判断处理"URI" 
	else
		rval = Send_File(URI, Socket);//向客户端发送信息

	if (rval == OK) {
		printf("The process is successfully finished!\n");
	}
	return OK;
}



const char* Judge_Method(char* method, int Socket) {
	//判断请求方式 
	if (strcmp(method, "GET") == 0) {
		return "GET";
	}
	else if (strcmp(method, "POST") == 0) {
		return "POST";
	}
	else {
		Error_Request_Method(Socket);
		return ERROR;
	}
}

int Judge_URI(char* URI, int Socket) {
	//判断请求URI 
	if (Inquire_File(URI) == ERROR) {
		File_not_Inquire(Socket);
		return ERROR;
	}
	else
		return OK;
}

int Send_Ifon(int Socket, const char* sendbuf, int Length) {
	//发送信息到客户端 
	int sendtotal = 0;//记录已经发送的字节总数
	int bufleft = 0;//包含要发送数据的字符指针
	int rval = 0;//上次发送的字符数

	bufleft = Length;
	while (sendtotal < Length)//当sendtotal==Length时，
		                      //已发完，不再进入循环
	{ //实际发送数   套接字  从哪个字符开始发送   发送的字符数
		rval = send(Socket, sendbuf + sendtotal,bufleft,     0);
		//实际发送数不一定等于指定字符数
		
		if (rval < 0) break;//检查错误
		sendtotal += rval;//从发送完的后一个字符开始发送
		bufleft -= rval;//减去已发送的字符
	}

	Length = sendtotal;

	return rval < 0 ? ERROR : OK;
}

int Error_Request_Method(int Socket) {
	//501 Not Implemented响应 
	const char* Method_err_line = "HTTP/1.1 501 Not Implemented\r\n";
	const char* cur_time = "";
	const char* Method_err_type = "Content-type: text/plain\r\n";
	const char* File_err_length = "Content-Length: 41\r\n";
	const char* Method_err_end = "\r\n";
	const char* Method_err_info = "The request method is not yet completed!\n";

	printf("The request method from client's request message is not yet completed!\n");

	if (Send_Ifon(Socket, Method_err_line, strlen(Method_err_line)) == ERROR) {
		printf("Sending method_error_line failed!\n");
		return ERROR;
	}

	if (Send_Ifon(Socket, Server_name, strlen(Server_name)) == ERROR) {
		printf("Sending Server_name failed!\n");
		return ERROR;
	}

	cur_time = Get_Data(cur_time);
	Send_Ifon(Socket, "Data: ", 6);
	if (Send_Ifon(Socket, cur_time, strlen(cur_time)) == ERROR) {
		printf("Sending cur_time error!\n");
		return ERROR;
	}

	if (Send_Ifon(Socket, Method_err_type, strlen(Method_err_type)) == ERROR) {
		printf("Sending method_error_type failed!\n");
		return ERROR;
	}

	if (Send_Ifon(Socket, Method_err_end, strlen(Method_err_end)) == ERROR) {
		printf("Sending method_error_end failed!\n");
		return ERROR;
	}

	if (Send_Ifon(Socket, Method_err_info, strlen(Method_err_info)) == ERROR) {
		printf("Sending method_error_info failed!\n");
		return ERROR;
	}

	return OK;
}

//判断文件是否存在
int Inquire_File(char* URI) {
	// Get the current working directory
	char cwd[BUF_SIZE];
	if (_getcwd(cwd, sizeof(cwd)) == NULL) {
		perror("getcwd() error");
		return ERROR;
	}

	// Construct the absolute path
	char abs_path[BUF_SIZE];
	snprintf(abs_path, sizeof(abs_path), "%s%s", cwd, URI);

	struct stat File_info;
	if (stat(abs_path, &File_info) == -1) {
		return ERROR;
	}
	else {
		return OK;
	}
}


int File_not_Inquire(int Socket) {
	const char* File_err_line = "HTTP/1.1 404 Not Found\r\n";
	const char* cur_time = "";
	const char* File_err_type = "Content-type: text/html\r\n";
	const char* File_err_end = "\r\n";

	FILE* file;
	struct stat file_stat;
	char sendbuf[BUF_SIZE];
	int send_length;

	// Get the current working directory
	char cwd[BUF_SIZE];
	if (_getcwd(cwd, sizeof(cwd)) == NULL) {
		perror("getcwd() error");
		return ERROR;
	}

	// Construct the absolute path to 404.html
	char abs_path[BUF_SIZE];
	snprintf(abs_path, sizeof(abs_path), "%s\\404.html", cwd);

	// Open and read 404.html
	file = fopen(abs_path, "rb");
	if (file != NULL) {
		fstat(_fileno(file), &file_stat);

		// Send 404 Not Found response
		if (Send_Ifon(Socket, File_err_line, strlen(File_err_line)) == ERROR) {
			printf("Sending file_error_line error!\n");
			fclose(file);
			return ERROR;
		}

		if (Send_Ifon(Socket, Server_name, strlen(Server_name)) == ERROR) {
			printf("Sending Server_name failed!\n");
			fclose(file);
			return ERROR;
		}

		cur_time = Get_Data(cur_time);
		Send_Ifon(Socket, "Date: ", 6);
		if (Send_Ifon(Socket, cur_time, strlen(cur_time)) == ERROR) {
			printf("Sending cur_time error!\n");
			fclose(file);
			return ERROR;
		}

		if (Send_Ifon(Socket, File_err_type, strlen(File_err_type)) == ERROR) {
			printf("Sending file_error_type error!\n");
			fclose(file);
			return ERROR;
		}

		// Calculate and send Content-Length
		char content_length[BUF_SIZE];
		snprintf(content_length, sizeof(content_length), "Content-Length: %lld\r\n", file_stat.st_size);
		if (Send_Ifon(Socket, content_length, strlen(content_length)) == ERROR) {
			printf("Sending file_error_length error!\n");
			fclose(file);
			return ERROR;
		}

		// Send end of header
		if (Send_Ifon(Socket, File_err_end, strlen(File_err_end)) == ERROR) {
			printf("Sending file_error_end error!\n");
			fclose(file);
			return ERROR;
		}

		// Send 404.html content
		while ((send_length = fread(sendbuf, 1, BUF_SIZE, file)) > 0) {
			if (Send_Ifon(Socket, sendbuf, send_length) == ERROR) {
				printf("Sending 404.html content error!\n");
				break;
			}
		}

		fclose(file);
	}
	else {
		printf("Failed to open 404.html!\n");
		return ERROR;
	}

	return OK;
}


int Send_File(char* URI, int Socket) {
	//将工作路径写入cwd
	char cwd[BUF_SIZE];
	if (_getcwd(cwd, sizeof(cwd)) == NULL) {
		perror("getcwd() error");
		return ERROR;
	}

	//将绝对路径写入abs_path(工作路径+URL)
	char abs_path[BUF_SIZE];
	snprintf(abs_path, sizeof(abs_path), "%s%s", cwd, URI);
	//以上是为了找到请求文件

	//定义 HTTP 响应信息的基础部分，
	// 包括响应状态行、当前时间、内容类型和内容长度
	// 200 OK响应
	const char* File_ok_line = "HTTP/1.1 200 OK\r\n";
	const char* cur_time = "";
	const char* File_ok_type = "";
	const char* File_ok_length = "Content-Length: ";
	const char* File_ok_end = "\r\n";

	FILE* file;
	struct stat file_stat;
	char Length[BUF_SIZE];
	char sendbuf[BUF_SIZE];
	int send_length;

	//将文件类型写入File_ok_type
	if (Judge_File_Type(abs_path, File_ok_type) == ERROR) {
		printf("The request file's type from client's request message is error!\n");
		return ERROR;//不支持的文件类型就报错
	}

	file = fopen(abs_path, "rb");
	//二进制打开请求的文件(只读)，指针指向开头

	if (file != NULL) 
	{
		//fstat函数获取文件的状态信息,填充到file_stat结构体中.
		// _fileno(file) 用于获取文件流的文件描述符(文件状态信息)
		fstat(_fileno(file), &file_stat);

		//这里使用 _itoa(int to string) 函数将文件的大小（以字节为单位）
		// 转换为字符串，存放在 Length 中，
		// 基数为 10（十进制）
		_itoa(file_stat.st_size, Length, 10);

		//发送"HTTP/1.1 200 OK\r\n"          strlen只计算'\0'前的字符数
		if (Send_Ifon(Socket, File_ok_line, strlen(File_ok_line)) == ERROR) {
			printf("Sending file_ok_line error!\n");
			return ERROR;
		}

		//发送"Server: Web Server 1.0 - BooLo\r\n"
		if (Send_Ifon(Socket, Server_name, strlen(Server_name)) == ERROR) {
			printf("Sending Server_name failed!\n");
			return ERROR;
		}

		//发送当前日期和时间
		cur_time = Get_Data(cur_time);
		Send_Ifon(Socket, "Date: ", 6);
		if (Send_Ifon(Socket, cur_time, strlen(cur_time)) == ERROR) {
			printf("Sending cur_time error!\n");
			return ERROR;
		}

		//                            将文件后缀写入 File_ok_type
		File_ok_type = Judge_File_Type(abs_path, File_ok_type);
		//发送后缀
		if (Send_Ifon(Socket, File_ok_type, strlen(File_ok_type)) == ERROR) {
			printf("Sending file_ok_type error!\n");
			return ERROR;
		}
		//发送文件大小（以字符串形式）                   
		if (Send_Ifon(Socket, File_ok_length, strlen(File_ok_length)) != ERROR) {
			if (Send_Ifon(Socket, Length, strlen(Length)) != ERROR) {
				if (Send_Ifon(Socket, "\n", 1) == ERROR) {
					printf("Sending file_ok_length error!\n");
					return ERROR;
				}
			}
		}

		//发送"\s\n"
		if (Send_Ifon(Socket, File_ok_end, strlen(File_ok_end)) == ERROR) {
			printf("Sending file_ok_end error!\n");
			return ERROR;
		}

		while (file_stat.st_size > 0) {
			if (file_stat.st_size < 1024) {
				send_length = fread(sendbuf, 1, file_stat.st_size, file);
				if (Send_Ifon(Socket, sendbuf, send_length) == ERROR) {
					printf("Sending file information error!\n");
					continue;
				}
				file_stat.st_size = 0;
			}
			else {
				send_length = fread(sendbuf, 1, 1024, file);
				if (Send_Ifon(Socket, sendbuf, send_length) == ERROR) {
					printf("Sending file information error!\n");
					continue;
				}
				file_stat.st_size -= 1024;
			}
		}
	}
	else {
		printf("The file is NULL!\n");
		return ERROR;
	}

	return OK;
}



const char* Judge_File_Type(char* URI, const char* content_type) {
	//文件类型判断 
	const char* suffix;

	//strrchr用于在一个字符串中查找一个字符最后一次出现的位置。
	// 如果找到了这个字符，它会返回一个指向该字符的指针，
	// 否则返回 NULL
	if ((suffix = strrchr(URI, '.')) != NULL)
		suffix = suffix + 1;//找到文件类型png mp3 ...

	if (strcmp(suffix, "html") == 0) {
		return content_type = "Content-type: text/html\r\n";
	}
	else if (strcmp(suffix, "jpg") == 0) {
		return content_type = "Content-type: image/jpg\r\n";
	}
	else if (strcmp(suffix, "png") == 0) {
		return content_type = "Content-type: image/png\r\n";
	}
	else if (strcmp(suffix, "gif") == 0) {
		return content_type = "Content-type: image/gif\r\n";
	}
	else if (strcmp(suffix, "txt") == 0) {
		return content_type = "Content-type: text/plain\r\n";
	}
	else if (strcmp(suffix, "xml") == 0) {
		return content_type = "Content-type: text/xml\r\n";
	}
	else if (strcmp(suffix, "rtf") == 0) {
		return content_type = "Content-type: text/rtf\r\n";
	}
	else if (strcmp(suffix, "js") == 0) {  // 添加对js文件的支持
		return content_type = "Content-type: application/javascript\r\n";
	}
	else if (strcmp(suffix, "css") == 0) {  // 添加对css文件的支持
		return content_type = "Content-type: text/css\r\n";
	}
	else if (strstr(URI, ".mp3") != NULL) {
		content_type = "Content-Type: audio/mpeg\r\n";
	}
	else
		return ERROR;
}

const char* Get_Data(const char* cur_time) {
	//获取Web服务器的当前时间作为响应时间 
	time_t curtime;
	time(&curtime);
	cur_time = ctime(&curtime);

	return cur_time;
}

const char* Post_Value(char* message) {
	//获取客户端POST请求方式的值 
	const char* suffix;

	if ((suffix = strrchr(message, '\n')) != NULL)
		suffix = suffix + 1;
	printf("\n\nPost Value: %s\n\n", suffix);

	return suffix;
}

int Logo() {
	//Web服务器标志信息 
	//printf("／￣￣￣￣￣￣￣￣￣\n");
	//printf("|　　程序启动了！\n");
	//printf("＼\n");
	//printf("　￣￣∨￣￣￣￣￣￣\n");
	//printf("　 ∧＿∧\n");
	//printf("　(　∧_∧)　\n");
	//printf("　(　 つつヾ\n");
	//printf("　 | ｜ |\n");
	//printf("　(＿_)＿)\n");
	//printf("\n");
	printf("start!\n");
	printf("___________________________________________________________\n\n");
	
	return OK;
}





//DWORD WINAPI Handle_Request_Message_Thread(LPVOID args) {
//	struct Handle_Request_Message_arg* requestArgs = (struct Handle_Request_Message_arg*)args;
//	char* message = requestArgs->message;
//	int Socket = requestArgs->Socket;
//
//	// 调用原始的处理函数
//	int result = Handle_Request_Message(message, Socket);
//
//	// 处理完毕后释放内存
//	free(requestArgs);
//	return (DWORD)result; // 返回处理结果
//}

//// 调用线程的函数
//void Handle_Request_Message_In_Thread(char* message, int Socket) {
//	struct Handle_Request_Message_arg* args = malloc(sizeof(struct Handle_Request_Message_arg));
//	args->message = message;
//	args->Socket = Socket;
//
//	HANDLE threadHandle = CreateThread(
//		NULL,                  // 默认安全性
//		0,                     // 默认堆栈大小
//		Handle_Request_Message_Thread, // 线程函数
//		args,                 // 参数传递
//		0,                     // 默认创建标志
//		NULL);                // 返回线程ID（可选）
//
//	if (threadHandle == NULL) {
//		printf("Failed to create thread\n");
//		free(args); // 线程创建失败时释放内存
//	}
//	else {
//		//CloseHandle(threadHandle); // 关闭线程句柄
//	}
//}




int load_Winsock()
{
	//加载一个Winsock库,保证后续调用
	WORD wVersionrequested;
	WSADATA wsaData;
	wVersionrequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionrequested, &wsaData) != 0) {
		printf("Failed to load Winsock!\n");
		system("pause");
		return -1;
	}
	printf("Succeed to load Winsock!\n");
	return 1;
}

void acceptclient(void* arg) 
{
	struct Handle_Request_Message_arg* argn = (struct Handle_Request_Message_arg*)arg;
	struct sockaddr_in ClientAddr = *(struct sockaddr_in*)argn->clientaddr;
	int rval, Length;
	Length = argn->length;
	char revbuf[BUF_SIZE];
	//判断是否accept成功
	SOCKET MessageSock = argn->message;
	if (MessageSock == INVALID_SOCKET) {
		printf("Failed to accept connection from client!\n");
		system("pause");
		exit(1);
	}
	printf("Succeed to accept connection from [%s:%d] !\n\n", inet_ntoa(ClientAddr.sin_addr), ntohs(ClientAddr.sin_port));

	/* 接收客户端请求数据 */
	memset(revbuf, 0, BUF_SIZE);	//每一个字节都用0来填充 
	rval = recv(MessageSock, revbuf, BUF_SIZE, 0);
	//revbuf[rval] = 0x00;//在字符串尾部添加'\0',没必要，
	// 字符串后面没用完的几百个字符都是'\0'

	//rval为recv返回的字符个数
	if (rval <= 0)
		printf("Failed to receive request message from client!\n");
	else {
		//输出请求数据内容
		printf("%s\n", revbuf);
		//处理请求
		Handle_Request_Message(revbuf, MessageSock);
	}


	closesocket(MessageSock);//处理完请求，关闭客户端套接字
	free(arg);
	//一个请求对应一个套接字
	printf("\n-----------------------------------------------------------\n");

}


void* get_voidptr_Request_Message_arg(SOCKET MessageSock,int Length, struct sockaddr_in* paddr)
{
	struct Handle_Request_Message_arg* arg = malloc(sizeof(struct Handle_Request_Message_arg));
	memset(arg, 0, sizeof(struct Handle_Request_Message_arg));
	arg->message = MessageSock;
	arg->length = Length;
	arg->clientaddr = paddr;
	return (void*)arg;
}

void initmain()
{
	
	SetConsoleOutputCP(CP_UTF8);


	// 加载Winsock 
	if (!load_Winsock())
	{
		printf("加载Winsock失败\n");
		return 0;
	}
}

int main(int argc, char* argv[]) {

	initmain();

	// 默认端口号
	int port = SERVER_PORT;

	// 如果通过命令行传入端口号，则使用该端口号
	if (argc == 2) {port = atoi(argv[1]);}

	// 创建服务器套接字
	SOCKET ServerSock;
	// 创建客户端套接字
	SOCKET MessageSock;

	// 初始化服务器套接字
	ServerSock = Server_Socket_Init(port);

	// 创建并初始化地址结构体
	struct sockaddr_in ClientAddr;
	memset(&ClientAddr, 0, sizeof(struct sockaddr_in));

	int rval;//临时变量，接收listen返回值，判断是否成功 
	const int Length = sizeof(struct sockaddr);//全局变量，存储struct sockaddr大小，方便传参

	//char revbuf[BUF_SIZE];

	Logo();//logo
	printf("Web Server is starting on port %d...\n\n", port);



	//setsockopt：
	//这是一个系统调用，用于设置套接字的各种选项。它的使用可以改变套接字的行为，比如最大连接数、超时等。
	//参数分析：
	//server_socket：这是之前创建的服务器套接字的描述符。
	// 通过该描述符，setsockopt能够找到并修改特定套接字的选项。
	// 
	//SOL_SOCKET：这是一个级别常量，
	// 告诉函数我们要设置的是套接字层的选项。
	// 
	//SO_REUSEADDR：这是我们要设置的选项，允许重用本地地址。
	// 它使得在程序结束后，短时间内再次绑定相同的地址和端口不被拒绝，
	// 尤其在服务器频繁启动和停止的情况下非常有用。
	// 
	//(const char*)&opt：这是指向选项值的指针。
	// 在这里，opt是一个整型变量，设置为1表示启用该选项。
	// 使用(const char*)& opt可以将其类型转换为指向字符的指针，
	// 以便符合函数参数的要求。
	
	//sizeof(opt)：这是选项值的大小，
	// 告诉setsockopt函数我们发送的数据有多大。
	// 
	//返回值：
	//ret将包含setsockopt调用的返回值。返回值为0表示成功，
	//- 1表示失败。
	//int ret = 0;//临时存储返回值
	//int opt = 1;//临时存储1
	//ret = setsockopt(ServerSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
	//////////////

	//优化后
	setsockopt(ServerSock, SOL_SOCKET, SO_REUSEADDR, (const char*)'\1', sizeof('\1'));
	////////////
	
	printf("\n-----------------------------------------------------------\n");

	while (OK)
	{
		// 启动监听
		rval = listen(ServerSock, BACKLOG);//listen 函数用于将套接字设置为被动模式，从而等待客户端连接
		
		//判断是否监听成功
		if (rval == SOCKET_ERROR)
		{
			printf("Failed to listen socket!\n");
			system("pause");
			exit(1);
		}
		printf("Listening the socket on port %d...\n", port);

		/* 接受客户端请求建立连接 */
		//通过 accept 函数接受一个连接请求。
		// 这个函数会阻塞，直到有客户端请求连接。
		//它将返回一个新的套接字 MessageSock，
		// 用于与特定客户端进行通信。
		// ClientAddr 用于存储客户端的地址信息
		//Length = sizeof(struct sockaddr);

		//获取端口
		MessageSock = accept(ServerSock, (SOCKADDR*)&ClientAddr, &Length);
		

		//struct Handle_Request_Message_arg* arg = malloc(sizeof(struct Handle_Request_Message_arg));
		//memset(arg, 0, sizeof(struct Handle_Request_Message_arg));
		//arg->message = MessageSock;
		//arg->length = Length;
		//arg->clientaddr = &ClientAddr;

		//struct Handle_Request_Message_arg* arg = get_voidptr_Request_Message_arg(MessageSock,Length,&ClientAddr);

		//记得尝试arg复用
		DWORD dwThreadID = 0;
		HANDLE handleFirst = CreateThread(NULL, 0, acceptclient, get_voidptr_Request_Message_arg(MessageSock, Length, &ClientAddr), 0, &dwThreadID);
		
	}

	closesocket(ServerSock);	//关闭套接字 
	WSACleanup();	//停止Winsock

	return OK;
}
