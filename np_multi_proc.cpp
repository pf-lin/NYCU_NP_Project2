#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <sys/shm.h> // add
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace std;

#define SHMKEY_USERINFO 7890
#define SHMKEY_MESSAGE 7891
#define PERMS 0666
#define MAXBUFSIZE 15000
#define MAXUSER 30
#define PROMPT "% "

struct NumberedPipe {
    int pipeCmdId; // the command id that the numbered pipe is connected to
    int numPipefd[2];
};

struct UserPipe {
    int fromId; // sender
    int toId;   // receiver
    int userPipefd[2];
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
    bool isUserPipeToErr = false;   // the user does not exist or the user pipe already exits (>999)
    bool isUserPipeFromErr = false; // the user does not exist or the user pipe does not exist (<998)
    int userPipeFromIndex = -1;     // user pipe index in userPipeList (for reading and closing user pipe)
    int userPipeToIndex = -1;       // user pipe index in userPipeList (for creating user pipe)
    int pipeNumber;
    int *to = nullptr;
    int *from = nullptr;
};

struct UserInfo {
    bool isLogin; // check if the user is login
    int id;       // range from 1 to 30
    char name[25];
    char ipPort[25];
    pid_t pid;
};

struct BroadcastMsg {
    char msg[MAXBUFSIZE];
};

// share memory
UserInfo *userList;
BroadcastMsg *shm_broadcast;

// FIFO
vector<UserPipe> userPipeList; // store user pipe

int cmdCount;                     // count the number of commands
vector<NumberedPipe> numPipeList; // store numbered pipe

int fd_null[2]; // for /dev/null
const string welcomeMessage = "****************************************\n"
                              "** Welcome to the information server. **\n"
                              "****************************************\n";

void signalTerminate(int signo) {
    shmctl(SHMKEY_USERINFO, IPC_RMID, 0);
    shmctl(SHMKEY_MESSAGE, IPC_RMID, 0);
    exit(0);
}

void signalBroadcast(int signo) {
    cout << shm_broadcast->msg << flush;
}

// Function to broadcast message to all users
void broadcastMessage(const string &msg) {
    memset(shm_broadcast->msg, 0, MAXBUFSIZE);
    strcpy(shm_broadcast->msg, msg.c_str());
    for (int idx = 1; idx <= MAXUSER; idx++) {
        if (userList[idx].isLogin) {
            kill(userList[idx].pid, SIGUSR1);
        }
    }
}

void initUserInfos(int idx) {
    userList[idx].isLogin = false;
    userList[idx].id = 0;
    strcpy(userList[idx].name, "(no name)");
    strcpy(userList[idx].ipPort, "");
    userList[idx].pid = -1;
}

void deleteUserPipe(int id) {
    for (int i = 0; i < userPipeList.size(); i++) {
        if (userPipeList[i].fromId == id || userPipeList[i].toId == id) {
            close(userPipeList[i].userPipefd[0]);
            close(userPipeList[i].userPipefd[1]);
            userPipeList.erase(userPipeList.begin() + i);
        }
    }
}

void userLoginMessage(int idx) {
    cout << welcomeMessage;
    string msg = "*** User '" + string(userList[idx].name) + "' entered from " + userList[idx].ipPort + ". ***\n";
    broadcastMessage(msg);
    cout << PROMPT;
}

tuple<int, int> userLogin(int msock) {
    // Accept the new connection
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    int ssock = accept(msock, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (ssock < 0) {
        cerr << "Failed to accept the new connection" << endl;
    }

    // Get the client IP address and port
    char ipBuf[INET_ADDRSTRLEN];
    string clientIP = inet_ntop(AF_INET, &clientAddr.sin_addr, ipBuf, sizeof(clientIP));
    string clientPort = to_string(ntohs(clientAddr.sin_port));
    string ipPort = clientIP + ":" + clientPort;

    // Find the first available user slot
    for (int idx = 1; idx <= MAXUSER; idx++) {
        if (!userList[idx].isLogin) {
            userList[idx].isLogin = true;
            userList[idx].id = idx;
            strcpy(userList[idx].ipPort, ipPort.c_str());
            return {ssock, userList[idx].id};
        }
    }
}

void userLogout(int userIndex) {
    if (userIndex != -1) {
        string msg = "*** User '" + string(userList[userIndex].name) + "' left. ***\n";
        broadcastMessage(msg);
        initUserInfos(userIndex);
        deleteUserPipe(userIndex);
        shmdt(userList);
        shmdt(shm_broadcast);
    }
}

void userPipeInMessage(int sourceId, UserInfo *user, const string &cmd, Process *process) {
    if (sourceId < 0 || sourceId > 30 || !userList[sourceId].isLogin) { // the source user does not exist
        process->isUserPipeFromErr = true;
        cout << "*** Error: user #" << sourceId << " does not exist yet. ***\n";
    }
    else {
        bool isUserPipeExist = false;
        for (int upIdx = 0; upIdx < userPipeList.size(); upIdx++) {
            if (userPipeList[upIdx].toId == user->id && userPipeList[upIdx].fromId == sourceId) { // user pipe exists
                string msg = "*** " + string(userList[user->id].name) + " (#" + to_string(user->id) + ") just received from " + userList[sourceId].name + " (#" + to_string(sourceId) + ") by '" + cmd + "' ***\n";
                broadcastMessage(msg);
                isUserPipeExist = true;
                process->userPipeFromIndex = upIdx;
                break;
            }
        }
        if (!isUserPipeExist) { // user pipe does not exist
            process->isUserPipeFromErr = true;
            cout << "*** Error: the pipe #" << sourceId << "->#" << user->id << " does not exist yet. ***\n";
        }
    }
}

void userPipeOutMessage(int targetId, UserInfo *user, const string &cmd, Process *process) {
    if (targetId < 0 || targetId > 30 || !userList[targetId].isLogin) { // the target user does not exist
        process->isUserPipeToErr = true;
        cout << "*** Error: user #" << targetId << " does not exist yet. ***\n";
    }
    else {
        bool isUserPipeExist = false;
        for (int i = 0; i < userPipeList.size(); i++) {
            if (userPipeList[i].fromId == user->id && userPipeList[i].toId == targetId) { // user pipe exists
                process->isUserPipeToErr = true;
                cout << "*** Error: the pipe #" << user->id << "->#" + to_string(targetId) << " already exists. ***\n";
                isUserPipeExist = true;
                break;
            }
        }
        if (!isUserPipeExist) { // user pipe does not exist
            // create a new user pipe
            UserPipe userPipe;
            userPipe.fromId = user->id;
            userPipe.toId = targetId;
            pipe(userPipe.userPipefd);
            userPipeList.push_back(userPipe);
            process->userPipeToIndex = userPipeList.size() - 1;
            // broadcast message
            string msg = "*** " + string(userList[user->id].name) + " (#" + to_string(user->id) + ") just piped '" + cmd + "' to " + userList[targetId].name + " (#" + to_string(targetId) + ") ***\n";
            broadcastMessage(msg);
        }
    }
}

// Function to handle user pipe message
void userPipeMessage(UserInfo *user, const string &input, Process *process) {
    for (int i = 0; i < process->args.size(); i++) {
        if (process->args[i][0] == '<') {
            int sourceId = stoi(process->args[i].substr(1));
            userPipeInMessage(sourceId, user, input, process);
        }
        else if (process->args[i][0] == '>') {
            if (i != process->args.size() - 1) {
                // handle the case (e.g. cat >1 <2)
                if (process->args[i + 1][0] == '<' && process->args[i + 1].size() > 1) {
                    int sourceId = stoi(process->args[i + 1].substr(1));
                    userPipeInMessage(sourceId, user, input, process);
                }
            }
            int targetId = stoi(process->args[i].substr(1));
            userPipeOutMessage(targetId, user, input, process);
            break;
        }
    }
}

// Use number pipe to classify cmd
vector<CommandInfo> splitCommand(UserInfo *user, const string &command) {
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
            cmdInfo.cmdId = cmdCount++;
            while (splitIndex <= i) {
                cmdInfo.cmdList.push_back(cmdSplitList[splitIndex]);
                splitIndex++;
            }
            cmdInfoList.push_back(cmdInfo);
        }
    }
    if (splitIndex < cmdSplitList.size()) {
        CommandInfo cmdInfo;
        cmdInfo.cmdId = cmdCount++;
        while (splitIndex < cmdSplitList.size()) {
            cmdInfo.cmdList.push_back(cmdSplitList[splitIndex]);
            splitIndex++;
        }
        cmdInfoList.push_back(cmdInfo);
    }

    return cmdInfoList;
}

// Parse command into each process (fork and execvp)
vector<Process> parseCommand(const CommandInfo &cmdInfo) {
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

bool builtInCommand(UserInfo *user, const CommandInfo &cmdInfo) {
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
        const char *env = getenv(cmdInfo.cmdList[1].c_str());
        if (env != NULL) {
            cout << env << endl;
        }
    }
    else if (cmdInfo.cmdList[0] == "exit") {
        userLogout(user->id);
        exit(0);
    }
    else if (cmdInfo.cmdList[0] == "who") {
        cout << "<ID>\t<nickname>\t<IP:port>\t<indicate me>\n";
        for (int idx = 1; idx <= MAXUSER; idx++) {
            if (userList[idx].isLogin) {
                cout << userList[idx].id << "\t" << userList[idx].name << "\t" << userList[idx].ipPort;
                if (idx == user->id) {
                    cout << "\t<-me";
                }
                cout << "\n";
            }
        }
    }
    else if (cmdInfo.cmdList[0] == "tell") {
        int targetId = stoi(cmdInfo.cmdList[1]);
        string msg = "";
        if (!userList[targetId].isLogin) { // the target user does not exist
            cout << "*** Error: user #" << targetId << " does not exist yet. ***\n";
        }
        else { // send message to target user
            msg += "*** " + string(user->name) + " told you ***: ";
            for (int i = 2; i < cmdInfo.cmdList.size(); i++) {
                msg += cmdInfo.cmdList[i];
                if (i != cmdInfo.cmdList.size() - 1) {
                    msg += " ";
                }
            }
            msg += "\n";
            memset(shm_broadcast->msg, 0, MAXBUFSIZE);
            strcpy(shm_broadcast->msg, msg.c_str());
            kill(userList[targetId].pid, SIGUSR1);
        }
    }
    else if (cmdInfo.cmdList[0] == "yell") {
        string msg = "*** " + string(user->name) + " yelled ***: ";
        for (int i = 1; i < cmdInfo.cmdList.size(); i++) {
            msg += cmdInfo.cmdList[i];
            if (i != cmdInfo.cmdList.size() - 1) {
                msg += " ";
            }
        }
        msg += "\n";
        broadcastMessage(msg);
    }
    else if (cmdInfo.cmdList[0] == "name") {
        bool isNameExist = false;
        for (int idx = 1; idx <= MAXUSER; idx++) {
            if (userList[idx].isLogin && userList[idx].name == cmdInfo.cmdList[1]) {
                cout << "*** User '" << cmdInfo.cmdList[1] << "' already exists. ***" << endl;
                isNameExist = true;
            }
        }
        if (!isNameExist) {
            strcpy(user->name, cmdInfo.cmdList[1].c_str());
            string msg = "*** User from " + string(user->ipPort) + " is named '" + user->name + "'. ***\n";
            broadcastMessage(msg);
        }
    }
    else {
        return false;
    }
    return true;
}

void execute(const Process &process) {
    char *argv[process.args.size() + 1];
    for (int i = 0; i < process.args.size(); i++) {
        if ((process.args[i][0] == '>' || process.args[i][0] == '<') && process.args[i].size() > 1) { // user pipe
            argv[i] = NULL;
        }
        else if (process.args[i] == "<") { // Implement "<" -- for demo
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
            argv[i] = (char *)process.args[i].c_str();
        }
    }
    argv[process.args.size()] = NULL;

    if (execvp(argv[0], argv) == -1) {
        cerr << "Unknown command: [" << argv[0] << "]." << endl;
        exit(0);
    }
}

// Find if there is a number pipe to pass to this command
int findPipeCmdId(const UserInfo &user, const vector<CommandInfo> &commands, int i) {
    for (int np = 0; np < numPipeList.size(); np++) {
        if (numPipeList[np].pipeCmdId == commands[i].cmdId) {
            return np;
        }
    }
    return -1;
}

// Check if the command has user pipe
bool hasUserPipe(const Process &process) {
    for (int i = 0; i < process.args.size(); i++) {
        if ((process.args[i][0] == '>' || process.args[i][0] == '<') && process.args[i].size() > 1) {
            return true;
        }
    }
    return false;
}

// Link user pipe
void linkUserPipe(Process *process) {
    if (process->userPipeFromIndex != -1) {
        process->from = userPipeList[process->userPipeFromIndex].userPipefd; // read from user pipe
    }
    if (process->userPipeToIndex != -1) {
        process->to = userPipeList[process->userPipeToIndex].userPipefd; // write to user pipe
    }
    // Error handling
    if (process->isUserPipeFromErr) {
        process->from = fd_null; // read from /dev/null
    }
    if (process->isUserPipeToErr) {
        process->to = fd_null; // write to /dev/null
    }
}

void executeProcess(UserInfo *user, vector<Process> &processList, const string &input, int cmdId, bool isNumPipeInput, int numPipeIndex) {
    pid_t pid;
    int pipefd[2][2];                                                    // pipefd[0] for odd process, pipefd[1] for even process
    for (int j = 0; j < processList.size(); j++) {                       // for each process
        if (processList[j].isNumberedPipe || processList[j].isErrPipe) { // create numbered pipe
            int numPipeCmdId = cmdId + processList[j].pipeNumber;

            // check if a numbered pipe connected to the same command has been established
            for (int np = 0; np < numPipeList.size(); np++) {
                if (numPipeList[np].pipeCmdId == numPipeCmdId) {
                    processList[j].to = numPipeList[np].numPipefd;
                    break;
                }
            }

            // if not, create a new numbered pipe
            if (processList[j].to == nullptr) {
                NumberedPipe numPipe;
                numPipe.pipeCmdId = numPipeCmdId;
                pipe(numPipe.numPipefd);
                numPipeList.push_back(numPipe);
                processList[j].to = numPipeList[numPipeList.size() - 1].numPipefd;
            }
        }
        if (j == 0 && isNumPipeInput /* There is a number pipe to write to*/) {
            processList[j].from = numPipeList[numPipeIndex].numPipefd; // read from number pipe
        }
        if (j > 0) {
            processList[j].from = pipefd[(j - 1) % 2];
        }
        if (j < processList.size() - 1) {
            processList[j].to = pipefd[j % 2];
            pipe(pipefd[j % 2]);
        }

        // Handle user pipe
        if (hasUserPipe(processList[j])) {
            userPipeMessage(user, input, &processList[j]);
            linkUserPipe(&processList[j]);
        }

        while ((pid = fork()) == -1) { // if fork() failed, wait for any one child process to finish
            waitpid(-1, NULL, 0);
        }

        auto process = processList.at(j); // by newb1er
        if (pid == 0) {                   // child process
            if (process.to != nullptr) {
                close(process.to[0]);
                dup2(process.to[1], STDOUT_FILENO);
                if (process.isErrPipe) {
                    dup2(process.to[1], STDERR_FILENO);
                }
                close(process.to[1]);
            }
            if (process.from != nullptr) {
                close(process.from[1]);
                dup2(process.from[0], STDIN_FILENO);
                close(process.from[0]);
            }
            execute(process);
        }
        else { // parent process
            while (waitpid(-1, NULL, WNOHANG))
                ; // wait for all child processes to finish (non-blocking waitpid())

            if (j == 0 && isNumPipeInput) { // close number pipe
                close(numPipeList[numPipeIndex].numPipefd[0]);
                close(numPipeList[numPipeIndex].numPipefd[1]);
            }
            if (j == 0 && process.userPipeFromIndex != -1) { // close user pipe
                close(userPipeList[process.userPipeFromIndex].userPipefd[0]);
                close(userPipeList[process.userPipeFromIndex].userPipefd[1]);
                userPipeList.erase(userPipeList.begin() + process.userPipeFromIndex);
            }
            if (j > 0) { // close pipe
                close(pipefd[(j - 1) % 2][0]);
                close(pipefd[(j - 1) % 2][1]);
            }
        }
    }

    // if the last process is number pipe or user pipe -> shouldn't wait
    if (processList.back().isNumberedPipe || processList.back().userPipeToIndex != -1) {
        usleep(50000);
        return;
    }
    // wait for the last process to finish
    waitpid(pid, NULL, 0);
}

// Function to execute each command
void executeCommand(UserInfo *user, const vector<CommandInfo> &commands, const string &input) {
    for (int i = 0; i < commands.size(); i++) { // for each command
        if (builtInCommand(user, commands[i])) {
            continue;
        }

        vector<Process> processList = parseCommand(commands[i]);

        bool isNumPipeInput = false;
        int numPipeIndex = findPipeCmdId(*user, commands, i);
        if (numPipeIndex != -1) {
            isNumPipeInput = true;
        }

        executeProcess(user, processList, input, commands[i].cmdId, isNumPipeInput, numPipeIndex);
    }
}

int shell(int idx) {
    // Get the current user
    UserInfo *user = &userList[idx];

    // Clear the environment variables
    clearenv();
    // Set the environment variables for the user
    setenv("PATH", "bin:.", 1);

    string input;
    vector<CommandInfo> commands;

    while (true) {
        getline(cin, input);
        input.erase(input.find_last_not_of(" \n\r\t") + 1); // remove trailing whitespace

        // Split the command by number pipe and error pipe
        commands = splitCommand(user, input);
        executeCommand(user, commands, input);

        // Print the command line prompt
        cout << PROMPT; // %
    }

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
    if (bind(serverSocketfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Error: server can't bind local address" << endl;
    }

    // Listen on the socket
    if (listen(serverSocketfd, MAXUSER) < 0) {
        cerr << "Error: server can't listen on socket" << endl;
    }

    return serverSocketfd;
}

void createSharedMemory() {
    // Create shared memory for user information
    int shmid_userInfo = shmget(SHMKEY_USERINFO, sizeof(UserInfo) * (MAXUSER + 1), PERMS | IPC_CREAT);
    if (shmid_userInfo < 0) {
        cerr << "Error: failed to create shared memory for user information" << endl;
    }
    userList = (UserInfo *)shmat(shmid_userInfo, 0, 0);
    if (userList == (UserInfo *)-1) {
        cerr << "Error: failed to attach shared memory for user information" << endl;
    }

    // Create shared memory for broadcast message
    int shmid_message = shmget(SHMKEY_MESSAGE, sizeof(BroadcastMsg), PERMS | IPC_CREAT);
    if (shmid_message < 0) {
        cerr << "Error: failed to create shared memory for broadcast message" << endl;
    }
    shm_broadcast = (BroadcastMsg *)shmat(shmid_message, 0, 0);
    if (shm_broadcast == (BroadcastMsg *)-1) {
        cerr << "Error: failed to attach shared memory for broadcast message" << endl;
    }
}

int main(int argc, char *argv[]) {
    // set the capacity of user pipe list
    userPipeList.reserve(500);

    // initial /dev/null
    fd_null[0] = open("/dev/null", O_RDWR);
    fd_null[1] = open("/dev/null", O_RDWR);

    signal(SIGINT, signalTerminate);
    signal(SIGUSR1, signalBroadcast);

    // Create a passive TCP socket and get its file descriptor (msock)
    int msock = passiveTCP(atoi(argv[1]));
    // int msock = passiveTCP(7000); // for testing

    createSharedMemory();

    // initial user information
    for (int i = 1; i <= MAXUSER; i++) {
        initUserInfos(i);
    }

    while (true) {
        auto [ssock, userIndex] = userLogin(msock);

        // Fork a child process to handle the new connection (Concurrent connection-oriented server)
        pid_t pid;
        while ((pid = fork()) == -1) { // if fork() failed, wait for any one child process to finish
            waitpid(-1, NULL, 0);
        }

        if (pid == 0) { // child process
            close(msock);
            // Redirect stdin, stdout, stderr to the new socket
            dup2(ssock, STDIN_FILENO);
            dup2(ssock, STDOUT_FILENO);
            dup2(ssock, STDERR_FILENO);
            close(ssock);
            userLoginMessage(userIndex);
            shell(userIndex);
        }
        else if (pid > 0) { // parent process
            userList[userIndex].pid = pid;
            close(ssock);
        }
    }

    return 0;
}
