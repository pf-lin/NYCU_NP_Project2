#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h> // add
#include <map> // add

using namespace std;

#define MAXBUFSIZE 15000
#define MAXUSER 30

struct NumberedPipe {
    int pipeCmdId; // the command id that the numbered pipe is connected to
    int numPipefd[2];
};

struct CommandInfo {
    vector<string> cmdList;
    int cmdId;
};

struct Process {
    vector<string> args;
    bool isOrdinaryPipe = false;
    bool isNumberedPipe = false;
    bool isErrPipe = false;
    int pipeNumber;
    int *to = nullptr;
    int *from = nullptr;
};

struct UserInfo {
    bool isLogin; // check if the user is login
    int id; // range from 1 to 30
    string name;
    string ipPort;
    int fd;
    map<string, string> env; // [var] [value] (e.g. [PATH] [bin:.])

    int cmdCount; // count the number of commands
    vector<NumberedPipe> numPipeList; // store numbered pipe
};

vector<UserInfo> userList(MAXUSER + 1); // store user information

const string welcomeMessage = "****************************************\n"
                              "** Welcome to the information server. **\n"
                              "****************************************\n";

// Use number pipe to classify cmd
vector<CommandInfo> splitCommand(UserInfo* user, const string& command) {
    // Split the command by ' ' (space)
    vector<string> cmdSplitList;
    string token;
    stringstream ss(command);
    while (ss >> token) {
        cmdSplitList.push_back(token);
    }
    ss.clear();
    ss.str("");

    // Combine cmdSplitList into a command
    vector<CommandInfo> cmdInfoList;
    int splitIndex = 0;
    for (int i = 0; i < cmdSplitList.size(); i++) {
        if ((cmdSplitList[i][0] == '|' || cmdSplitList[i][0] == '!') && cmdSplitList[i].size() > 1) {
            CommandInfo cmdInfo;
            cmdInfo.cmdId = user->cmdCount++;
            while (splitIndex <= i) {
                cmdInfo.cmdList.push_back(cmdSplitList[splitIndex]);
                splitIndex++;
            }
            cmdInfoList.push_back(cmdInfo);
        }
    }
    if (splitIndex < cmdSplitList.size()) {
        CommandInfo cmdInfo;
        cmdInfo.cmdId = user->cmdCount++;
        while (splitIndex < cmdSplitList.size()) {
            cmdInfo.cmdList.push_back(cmdSplitList[splitIndex]);
            splitIndex++;
        }
        cmdInfoList.push_back(cmdInfo);
    }

    return cmdInfoList;
}

// Parse command into each process (fork and execvp)
vector<Process> parseCommand(const CommandInfo& cmdInfo) {
    vector<Process> processList;
    int cmdListIndex = 0;
    for (int i = 0; i < cmdInfo.cmdList.size(); i++) {
        if ((cmdInfo.cmdList[i][0] == '|' || cmdInfo.cmdList[i][0] == '!') && cmdInfo.cmdList[i].size() > 1) {
            Process process;
            if (cmdInfo.cmdList[i][0] == '|') // numbered pipe
                process.isNumberedPipe = true;
            else // error pipe
                process.isErrPipe = true;

            process.pipeNumber = stoi(cmdInfo.cmdList[i].substr(1));
            while (cmdListIndex < i) {
                process.args.push_back(cmdInfo.cmdList[cmdListIndex]);
                cmdListIndex++;
            }
            cmdListIndex++;
            processList.push_back(process);
        }
        else if (cmdInfo.cmdList[i][0] == '|' && cmdInfo.cmdList[i].size() == 1) { // ordinary pipe
            Process process;
            process.isOrdinaryPipe = true;
            while (cmdListIndex < i) {
                process.args.push_back(cmdInfo.cmdList[cmdListIndex]);
                cmdListIndex++;
            }
            cmdListIndex++;
            processList.push_back(process);
        }
    }
    if (cmdListIndex < cmdInfo.cmdList.size()) {
        Process process;
        while (cmdListIndex < cmdInfo.cmdList.size()) {
            process.args.push_back(cmdInfo.cmdList[cmdListIndex]);
            cmdListIndex++;
        }
        processList.push_back(process);
    }
    return processList;
}

bool build_in_command(const CommandInfo& cmdInfo) {
    if (cmdInfo.cmdList[0] == "setenv") {
        // TODO: input validation (not in spec but better to have it) -- by newb1er
        if (cmdInfo.cmdList.size() != 3) {
            cerr << "Invalid number of arguments for setenv command." << endl;
            return false;
        }
        setenv(cmdInfo.cmdList[1].c_str(), cmdInfo.cmdList[2].c_str(), 1);
    }
    else if (cmdInfo.cmdList[0] == "printenv") {
        // TODO: input validation (not in spec but better to have it) -- by newb1er
        if (cmdInfo.cmdList.size() != 2) {
            cerr << "Invalid number of arguments for printenv command." << endl;
            return false;
        }
        const char* env = getenv(cmdInfo.cmdList[1].c_str());
        if (env != NULL) {
            cout << env << endl;
        }
    }
    else if (cmdInfo.cmdList[0] == "exit") {
        exit(0);
    }
    else {
        return false;
    }
    return true;
}

void execute(const Process& process) {
    char* argv[process.args.size() + 1];
    for (int i = 0; i < process.args.size(); i++) {
        if (process.args[i] == "<") { // Implement "<" -- for demo
            int fd = open(process.args[i + 1].c_str(), O_RDONLY);
            dup2(fd, STDIN_FILENO);
            close(fd);
            argv[i] = NULL;
        }
        else if (process.args[i] == ">") { // file redirection
            int fd = open(process.args[i + 1].c_str(), O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
            dup2(fd, STDOUT_FILENO);
            close(fd);
            argv[i] = NULL;
        }
        else {
            argv[i] = (char*)process.args[i].c_str();
        }
    }
    argv[process.args.size()] = NULL;

    if (execvp(argv[0], argv) == -1) {
        cerr << "Unknown command: [" << argv[0] << "]." << endl;
        exit(0);
    }
}

// Find if there is a number pipe to pass to this command
int findPipeCmdId(UserInfo* user, const vector<CommandInfo>& commands, int i) {
    for (int np = 0; np < user->numPipeList.size(); np++) {
        if (user->numPipeList[np].pipeCmdId == commands[i].cmdId) {
            return np;
        }
    }
    return -1;
}

void executeProcess(UserInfo* user, vector<Process>& processList, int cmdId, bool isNumPipeInput, int numPipeIndex) {
    pid_t pid;
    int pipefd[2][2]; // pipefd[0] for odd process, pipefd[1] for even process
    for (int j = 0; j < processList.size(); j++) { // for each process
        if (processList[j].isNumberedPipe || processList[j].isErrPipe) { // create numbered pipe
            int numPipeCmdId = cmdId + processList[j].pipeNumber;

            // check if a numbered pipe connected to the same command has been established
            for (int np = 0; np < user->numPipeList.size(); np++) {
                if (user->numPipeList[np].pipeCmdId == numPipeCmdId) {
                    processList[j].to = user->numPipeList[np].numPipefd;
                    break;
                }
            }

            // if not, create a new numbered pipe
            if (processList[j].to == nullptr) {
                NumberedPipe numPipe;
                numPipe.pipeCmdId = numPipeCmdId;
                pipe(numPipe.numPipefd);
                user->numPipeList.push_back(numPipe);
                processList[j].to = user->numPipeList[user->numPipeList.size() - 1].numPipefd;
            }
        }
        if (j == 0 && isNumPipeInput/* There is a number pipe to write to*/) {
            processList[j].from = user->numPipeList[numPipeIndex].numPipefd; // read from number pipe
        }
        if (j > 0) {
            processList[j].from = pipefd[(j - 1) % 2];
        }
        if (j < processList.size() - 1) {
            processList[j].to = pipefd[j % 2];
            pipe(pipefd[j % 2]);
        }

        while ((pid = fork()) == -1) { // if fork() failed, wait for any one child process to finish
            waitpid(-1, NULL, 0);
        }

        if (pid == 0) { // child process
            auto process = processList.at(j); // by newb1er
            if (process.to != nullptr) {
                close(process.to[0]);
                dup2(process.to[1], STDOUT_FILENO);
                if (process.isErrPipe) {
                    dup2(process.to[1], STDERR_FILENO);
                }
                close(process.to[1]);
            } else { // if the process is the last one
                dup2(STDOUT_FILENO, user->fd);
                dup2(STDERR_FILENO, user->fd);
            }
            if (process.from != nullptr) {
                close(process.from[1]);
                dup2(process.from[0], STDIN_FILENO);
                close(process.from[0]);
            }
            execute(process);
        }
        else { // parent process
            while (waitpid(-1, NULL, WNOHANG)); // wait for all child processes to finish (non-blocking waitpid())

            if (j == 0 && isNumPipeInput) { // close number pipe
                close(user->numPipeList[numPipeIndex].numPipefd[0]);
                close(user->numPipeList[numPipeIndex].numPipefd[1]);
            }
            if (j > 0) { // close pipe
                close(pipefd[(j - 1) % 2][0]);
                close(pipefd[(j - 1) % 2][1]);
            }
        }
    }
    if (!processList.back().isNumberedPipe) { // if the last process is not a numbered pipe, wait for it to finish
        waitpid(pid, NULL, 0);
    }
    else {
        usleep(50000);
    }
}

// Function to execute each command
void executeCommand(UserInfo* user, const vector<CommandInfo>& commands) {
    for (int i = 0; i < commands.size(); i++) { // for each command
        if (build_in_command(commands[i])) {
            continue;
        }
        
        vector<Process> processList = parseCommand(commands[i]);

        bool isNumPipeInput = false;
        int numPipeIndex = findPipeCmdId(user, commands, i);
        if (numPipeIndex != -1) {
            isNumPipeInput = true;
        }

        executeProcess(user, processList, commands[i].cmdId, isNumPipeInput, numPipeIndex);
    }
}

int getUserIndex(int fd) {
    for (int idx = 1; idx <= MAXUSER; idx++) {
        if (userList[idx].fd == fd) {
            return idx;
        }
    }
    return -1;
}

int shell(int fd) {
    char buf[MAXBUFSIZE];
    memset(buf, 0, sizeof(buf));
    read(fd, buf, sizeof(buf));

    string input(buf);
    vector<CommandInfo> commands;

    // Redirect stdout, stderr
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    // Get the current user
    int userIndex = getUserIndex(fd);
    UserInfo* user = &userList.at(userIndex);

    setenv("PATH", "bin:.", 1); // initial PATH is bin/ and ./

    commands = splitCommand(user, input);
    if (commands.back().cmdList[0] == "exit") {
        return -1;
    }
    executeCommand(user, commands);

    // Print the command line prompt
    write(fd, "% ", 2);

    return 0;
}

// Function to create a passive TCP socket, and return its file descriptor
int passiveTCP(int port) {
    // Create a socket for the server
    int serverSocketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketfd < 0) {
        cerr << "Error: server can't open stream socket" << endl;
    }

    // Set up the server address
    struct sockaddr_in serverAddr;
    // Configure settings of the server address struct
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(serverAddr.sin_zero, 0, sizeof(serverAddr.sin_zero));

    // Set socket to be reusable
    int optval = 1;
    if (setsockopt(serverSocketfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        cerr << "Error: server can't set socket to be reusable" << endl;
    }

    // Bind the socket to the server address
    if (bind(serverSocketfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Error: server can't bind local address" << endl;
    }

    // Listen on the socket
    if (listen(serverSocketfd, MAXUSER) < 0) {
        cerr << "Error: server can't listen on socket" << endl;
    }

    return serverSocketfd;
}

void initUserInfos(int idx) {
    userList[idx].isLogin = false;
    userList[idx].id = 0;
    userList[idx].name = "(no name)";
    userList[idx].ipPort = "";
    userList[idx].fd = -1;
    userList[idx].env.clear();
    userList[idx].env["PATH"] = "bin:.";
    userList[idx].cmdCount = 0;
    userList[idx].numPipeList.clear();
}

void broadcastMessage(const string& msg) {
    for (int idx = 1; idx <= MAXUSER; idx++) {
        if (userList[idx].isLogin) {
            write(userList[idx].fd, msg.c_str(), msg.size());
        }
    }
}

void userLogin(int msock, fd_set& afds) {
    // Accept the new connection
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    int ssock = accept(msock, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (ssock < 0) {
        cerr << "Failed to accept the new connection" << endl;
    }
    // Add the new client socket to the file descriptor set
    FD_SET(ssock, &afds);

    // Get the client IP address and port
    char ipBuf[INET_ADDRSTRLEN];
    string ip = inet_ntoa(clientAddr.sin_addr);
    string clientIP = inet_ntop(AF_INET, &clientAddr.sin_addr, ipBuf, sizeof(clientIP));
    string clientPort = to_string(ntohs(clientAddr.sin_port));

    write(ssock, welcomeMessage.c_str(), welcomeMessage.size());

    // Find the first available user slot
    for (int idx = 1; idx <= MAXUSER; idx++) {
        if (!userList[idx].isLogin) {
            userList[idx].isLogin = true;
            userList[idx].id = idx;
            userList[idx].ipPort = clientIP + ":" + clientPort;
            userList[idx].fd = ssock;

            string msg = "*** User '" + userList[idx].name + "' entered from " + userList[idx].ipPort + ". ***\n";
            broadcastMessage(msg);
            break;
        }
    }

    // Print the command line prompt
    write(ssock, "% ", 2);
}

int main(int argc, char *argv[]) {
    // initial PATH is bin/ and ./
    setenv("PATH", "bin:.", 1);
    
    int msock = passiveTCP(atoi(argv[1]));

    // Set up the file descriptor set for select
    // int nfds = getdtablesize(); // get the maximum number of file descriptors (根據系統而定)
    int nfds = FD_SETSIZE; // 1024
    fd_set rfds;
    fd_set afds;
    FD_ZERO(&afds);
    FD_SET(msock, &afds);

    // initial user information
    for (int i = 1; i <= MAXUSER; i++) {
        initUserInfos(i);
    }

    // Store stdin, stdout, stderr
    int storeStd[3];
    storeStd[0] = dup(STDIN_FILENO);
    storeStd[1] = dup(STDOUT_FILENO);
    storeStd[2] = dup(STDERR_FILENO);

    while (true) {
        // Copy the file descriptor set
        memcpy(&rfds, &afds, sizeof(rfds)); // copy afds to rfds

        // Wait for activity on any of the sockets
        if (select(nfds, &rfds, NULL, NULL, NULL) < 0) { // 直到有訊息進來才會繼續 (system call)
            cerr << "Error in select" << endl;
        }

        // Check if there is a new incoming connection
        if (FD_ISSET(msock, &rfds)) {
            userLogin(msock, afds);
        }

        // Check for activity on client sockets
        for (int fd = 0; fd < nfds; ++fd) {
            if (fd != msock && FD_ISSET(fd, &rfds)) {
                // TODO: Read the command from the client socket
                // run shell
                int status = shell(fd);
                if (status == -1) { // exit
                    // Find the user index
                    int userIndex = getUserIndex(fd);
                    if (userIndex != -1) {
                        string msg = "*** User '" + userList[userIndex].name + "' left. ***\n";
                        broadcastMessage(msg);
                        initUserInfos(userIndex);
                    }
                    close(fd);
                    FD_CLR(fd, &afds);
                }
            }
        }

        // Restore stdin, stdout, stderr
        dup2(storeStd[0], STDIN_FILENO);
        dup2(storeStd[1], STDOUT_FILENO);
        dup2(storeStd[2], STDERR_FILENO);
    }

    return 0;
}
