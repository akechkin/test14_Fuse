

// only API version 30 or greater is supported
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include "../utils.hpp"

// fs
#include <dirent.h>
#include <sys/stat.h>

static const char *mountPoint = "/home/as/mntTest/my-fs\0";
static const char *mirrorPoint = "/home/as/mntTest/mirror\0";

static const char *hidenFileName = "HidenFile.txt\0";
static const char *hidenFileContent = "Данный файл доступен только из текущей файловой системы!\nОтображается в любой директории!\nНедоступен для редактирования!\0";

char *path_alloc(size_t *psize);
char *getPathBuf(size_t *psize);
char *addMirrorPoint(const char *path, const char *mirror);


static void *test_init(struct fuse_conn_info *conn,
                       struct fuse_config *cfg)
{
        (void)conn;
        cfg->kernel_cache = 1;
        DBG_LOG("-----------");
        return NULL;
}

static int test_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
        (void)fi;
        int res = 0;

        DBG_LOG("path: %s", path);

        char *pathBuf = addMirrorPoint(path, mirrorPoint);
        if (!pathBuf)
        {
                return -ENOENT;
        }

        memset(stbuf, 0, sizeof(struct stat));

        if (strstr(path + 1, hidenFileName) != 0)
        {
                DBG_LOG("compare path: %s, hidenFileName: %s", path + 1, hidenFileName);
                stbuf->st_mode = S_IFREG | 0444;
                stbuf->st_nlink = 1;
                stbuf->st_size = strlen(hidenFileContent);
        }
        else
        {
                if (lstat(pathBuf, stbuf) < 0)
                        return -ENOENT;
        }

        DBG_LOG("stbuf->st_mode: %d", stbuf->st_mode);
        DBG_LOG("stbuf->st_nlink: %d", stbuf->st_nlink);
        DBG_LOG("stbuf->st_size: %d", stbuf->st_size);

        // if (strcmp(path, "/") == 0) {
        //         stbuf->st_mode = S_IFDIR | 0755;
        //         stbuf->st_nlink = 2;
        // } else if (strcmp(path+1, options.filename) == 0) {
        //         stbuf->st_mode = S_IFREG | 0444;
        //         stbuf->st_nlink = 1;
        //         stbuf->st_size = strlen(options.contents);
        // } else
        //         res = -ENOENT;

        return res;
}

static int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
        (void)offset;
        (void)fi;
        (void)flags;

        DIR *pd;
        struct dirent *pdir;

        char *pathBuf = addMirrorPoint(path, mirrorPoint);
        if (!pathBuf)
                return -ENOENT;

        if ((pd = opendir(pathBuf)) == NULL) /* каталог недоступен */
                return -ENOENT;

        while ((pdir = readdir(pd)) != NULL)
        {
                // if (strcmp(pdir->d_name, ".") == 0 ||
                //     strcmp(pdir->d_name, "..") == 0)
                //         continue;                   /* пропустить каталоги "." и ".." */
                DBG_LOG("папка: %s", pdir->d_name);
                filler(buf, pdir->d_name, NULL, 0, 0);
        }

        filler(buf, hidenFileName, NULL, 0, 0);

        // if (strcmp(path, "/") != 0)
        //         return -ENOENT;

        // filler(buf, ".", NULL, 0, 0);
        // filler(buf, "..", NULL, 0, 0);
        // filler(buf, options.filename, NULL, 0, 0);

        return 0;
}

static int test_open(const char *path, struct fuse_file_info *fi)
{
        DBG_LOG("-----------");

        // if ((fi->flags & O_ACCMODE) != O_RDONLY)
        //         return -EACCES;

        char *pathBuf = addMirrorPoint(path, mirrorPoint);
        if (!pathBuf)
                return -ENOENT;

        DBG_LOG("open param: path:%s", path);

        fi->fh = open(pathBuf, (fi->flags & O_ACCMODE));

        return 0;
}

static int test_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{

        char *pathBuf = addMirrorPoint(path, mirrorPoint);
        if (!pathBuf)
                return -ENOENT;

        if (strstr(path + 1, hidenFileName) != 0)
        {
                memcpy(buf, hidenFileContent, strlen(hidenFileContent));
                return size;
        }

        DBG_LOG("read param:path:%s, buf: %p, size: %d, offset: %d, fd: %d",
                pathBuf, buf, size, offset);

        lseek(fi->fh, offset, 0);
        read(fi->fh, buf, size);

        return size;
}
static int test_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{

        char *pathBuf = addMirrorPoint(path, mirrorPoint);
        if (!pathBuf)
                return -ENOENT;

        DBG_LOG("write param:path:%s, buf: %p, size: %d, offset: %d, fd: %d",
                pathBuf, buf, size, offset);

        lseek(fi->fh, offset, 0);
        write(fi->fh, buf, size);

        return size;
}

static const struct fuse_operations test_oper = {
    .init = test_init,
    .getattr = test_getattr,
    .readdir = test_readdir,
    .open = test_open,
    .read = test_read,
    .write = test_write};

int main(int argc, char *argv[])
{
        int ret;
        struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
        fuse_opt_add_arg(&args, "");
        fuse_opt_add_arg(&args, "-odefault_permissions");
        fuse_opt_add_arg(&args, "-oauto_unmount");
        fuse_opt_add_arg(&args, "-odebug");
        fuse_opt_add_arg(&args, mountPoint);

        DBG_LOG("-----------");

        ret = fuse_main(args.argc, args.argv, &test_oper, NULL);
        fuse_opt_free_args(&args);
        return ret;
}

#ifdef PATH_MAX
static long pathmax = PATH_MAX;
#else
static long pathmax = 0;
#endif
char *path_alloc(size_t *psize)
{

        char *ptr;
        size_t size;

        static long int posix_version = 0;
        static long int xsi_version = 0;

        if (posix_version == 0)
                posix_version = sysconf(_SC_VERSION);

        if (xsi_version == 0)
                xsi_version = sysconf(_SC_XOPEN_VERSION);

        if (pathmax == 0)
        {
                errno = 0;
                if ((pathmax = pathconf("/", _PC_PATH_MAX)) < 0)
                {
                        if (errno == 0)
                                pathmax = 4096;
                        else
                                return NULL;
                }
                else
                {
                        pathmax++; /* добавить 1, так как путь относительно корня */
                }
        }

        /*
         * До версии POSIX.1-2001 не гарантируется, что PATH_MAX включает
         * завершающий нулевой байт. То же для XPG3.
         */
        if ((posix_version < 200112L) && (xsi_version < 4))
                size = pathmax + 1;
        else
                size = pathmax;

        // DBG_LOG("malloc size: %d", size);

        if ((ptr = malloc(size)) == NULL)
        {
                // err_sys("malloc error for pathname");
                exit(-1);
        }

        // DBG_LOG("malloc ret: %p", ptr);

        if (psize != NULL)
                *psize = size;
        return (ptr);
}

char *getPathBuf(size_t *psize)
{

        static char *buf = NULL;

        static size_t size = 0;

        // DBG_LOG("buf p: %p, psize: %d", *psize);

        if (buf == NULL)
        {
                buf = path_alloc(psize);
                size = *psize;
        }
        // DBG_LOG("buf p: %p, psize: %d", *psize);

        *psize = size;
        return buf;
}

char *addMirrorPoint(const char *path, const char *mirror)
{
        size_t size = 0;

        if (!path || !mirror)
        {
                return NULL;
        }

        char *pathBuf = getPathBuf(&size);

        // DBG_LOG("pathBuf size: %d", size);

        if (pathBuf)
        {
                memset(pathBuf, 0, size);
                strcpy(pathBuf, mirrorPoint);
                strcat(pathBuf, path);
        }

        // DBG_LOG("path: %s, mirror: %s", path,mirror);
        // DBG_LOG("pathBuf: %p, size: %d, data: %s", pathBuf,size,pathBuf);
        return pathBuf;
}