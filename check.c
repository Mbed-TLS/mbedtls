#include <stdio.h>
#include <string.h>

#define PSDLEN 6

void inputPsd(char *str)    /*处理输入*/
{
    int i;

    for(i = 0; i < PSDLEN; i++)
    {
        while(1)
        {
            str[i] = getchar();
            if(str[i] == '\b')           /*处理退格键*/
            {
                i--;
                if(i < 0)
                {
                    i = 0;
                }
                else
                {
                    printf("\b \b");
                }
                continue;
            }
            else if(str[i] == '\r')      /*处理回车键*/
            {
                continue;
            }
            else
            {
                printf("*");
                break;
            }
        }
    }
    str[i] = '\0';
    printf("\n");
}

int checkFirst()              /*检测是否是第一次使用*/
{
    FILE *fp;
    if((fp = fopen("psd.dat", "rb")) == NULL)
    {
        return 1;
    }
    fclose(fp);
    return 0;
}

void firstUse()               /*第一次使用 需要输入密码*/
{
    FILE *fp;
    int i;
    char passwd[PSDLEN + 1];
    char checkPsd[PSDLEN + 1];

    if((fp = fopen("psd.dat", "wb")) == NULL)
    {
        printf("Creat password error!\n");
        exit(1);
    }
    while(1)
    {
        printf("Please input password:");
        inputPsd(passwd);

        printf("\nPlease input password again:");
        inputPsd(checkPsd);

        if(!strcmp(passwd, checkPsd))
        {
            break;
        }
        printf("\ncheck password error! \n");
    }
    fwrite(passwd, sizeof(char), PSDLEN, fp);
    fclose(fp);
}

void login()                 /*核对密码，并登录*/
{
    FILE *fp;
    int i, num = 3;
    char passwd[PSDLEN + 1];
    char checkPsd[PSDLEN + 1];

    if((fp = fopen("psd.dat", "rb")) == NULL)
    {
        puts("Open psd.dat error");
        exit(1);
    }
    fread(passwd, sizeof(char), PSDLEN, fp);
    fclose(fp);
    passwd[PSDLEN] = '\0';

    printf("Please input password to login");
    while(num)
    {
        printf("you have %d chances to try:\n", num);
        inputPsd(checkPsd);
        if(!strcmp(passwd, checkPsd))
        {
            break;
        }
        puts("\npassword error,Please input again");
        num--;
    }
    if(!num)
    {
        puts("Press any key to exit...");
        getchar();
        exit(0);
    }
    else
    {
        puts("\n--------\nWelcome!\n--------\n");
    }
}

void main()
{
    if(checkFirst())
    {
        firstUse();
    }
    else
        login();

    getchar();
}
