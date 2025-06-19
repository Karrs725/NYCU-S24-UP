/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "maze.h"

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

maze_t mazes[_MAZE_MAXUSER];
int maze_in_use[_MAZE_MAXUSER] = {0};
int maze_pid[_MAZE_MAXUSER] = {0};

static int maze_dev_open(struct inode *i, struct file *f) {
	// printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {
	// TODO: Reset all mazes
	for(int i = 0; i < _MAZE_MAXUSER; i++) {
		if(maze_pid[i] == current->pid) {
			for(int j = 0; j < mazes[i].h; j++){
				for(int k = 0; k < mazes[i].w; k++){
					mazes[i].blk[j][k] = 0;
				}
			}
			maze_in_use[i] = 0;
			maze_pid[i] = 0;
			mazes[i].w = 0;
			mazes[i].h = 0;
			mazes[i].sx = 0;
			mazes[i].sy = 0;
			mazes[i].ex = 0;
			mazes[i].ey = 0;
			mazes[i].curx = 0;
			mazes[i].cury = 0;
			break;
		}
	}

	// printk(KERN_INFO "maze: device closed.\n");
	return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// TODO: deal with maze representation
	int can_find = 0;
	for(int i = 0; i < _MAZE_MAXUSER; i++) {
		if(maze_pid[i] == current->pid) {
			can_find = 1;
			len = mazes[i].w * mazes[i].h;
			char *seq = kmalloc(mazes[i].w * mazes[i].h, GFP_KERNEL);
			for(int j = 0; j < mazes[i].h; j++){
				for(int k = 0; k < mazes[i].w; k++){
					seq[j * mazes[i].w + k] = mazes[i].blk[j][k];
				}
			}
			if(copy_to_user(buf + *off, seq, len)){
				kfree(seq);
				return -EBUSY;
			}
			kfree(seq);
			break;
		}
	}

	if(can_find == 0)
		return -EBADFD;

	// printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	if(len % sizeof(coord_t) != 0)
		return -EINVAL;
	
	coord_t *coords = kmalloc(len, GFP_KERNEL);
	if(copy_from_user(coords, (coord_t *)buf, len))	{
		kfree(coords);
		return -EBUSY;
	}

	int can_find = 0;
	for(int i = 0; i < _MAZE_MAXUSER; i++) {
		if(maze_pid[i] == current->pid) {
			can_find = 1;
			for(int j = 0; j < len / sizeof(coord_t); j++){
				coord_t coord = coords[j];
				if(mazes[i].blk[mazes[i].cury + coord.y][mazes[i].curx + coord.x] == 0) {
					mazes[i].curx += coord.x;
					mazes[i].cury += coord.y;
				}
			}
			break;
		}
	}

	if(can_find == 0)
		return -EBADFD;

	kfree(coords);

	// printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	
	coord_t coord;
	int can_find = 0;
	switch (cmd){
		case MAZE_CREATE:
			if(copy_from_user(&coord, (coord_t *)arg, sizeof(coord_t)))
				return -EBUSY;

			if(coord.x < 0 || coord.x > _MAZE_MAXX || coord.y < 0 || coord.y > _MAZE_MAXY)
				return -EINVAL;

			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid)
					return -EEXIST;
			}

			int is_vacant = 0;
			int current_maze;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_in_use[i] == 0) {
					current_maze = i;
					is_vacant = 1;
					maze_in_use[i] = 1;
					maze_pid[i] = current->pid;
					mazes[i].w = coord.x;
					mazes[i].h = coord.y;
					mazes[i].sx = get_random_u32() % (mazes[i].w - 2) + 1;
					mazes[i].sy = get_random_u32() % (mazes[i].h - 2) + 1;
					mazes[i].ex = get_random_u32() % (mazes[i].w - 2) + 1;
					mazes[i].ey = get_random_u32() % (mazes[i].h - 2) + 1;
					mazes[i].curx = mazes[i].sx;
					mazes[i].cury = mazes[i].sy;
					break;
				}
			}

			// int x_diff = mazes[current_maze].ex - mazes[current_maze].sx;
			// int y_diff = mazes[current_maze].ey - mazes[current_maze].sy;

			if(is_vacant == 0)
				return -ENOMEM;
			
			for(int i = 0; i < mazes[current_maze].h; i++){
				for(int j = 0; j < mazes[current_maze].w; j++){
					if(i == 0 || j == 0 || i == mazes[current_maze].h - 1 || j == mazes[current_maze].w - 1) {
						mazes[current_maze].blk[i][j] = 1;
					}
					else if(i == mazes[current_maze].sy || j == mazes[current_maze].sx || i == mazes[current_maze].ey || j == mazes[current_maze].ex) {
						mazes[current_maze].blk[i][j] = 0;
					}
					else {
						mazes[current_maze].blk[i][j] = get_random_u32() % 2;
					}
				}
			}
			break;

		case MAZE_RESET:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					mazes[i].curx = mazes[i].sx;
					mazes[i].cury = mazes[i].sy;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_DESTROY:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					for(int j = 0; j < mazes[i].h; j++){
						for(int k = 0; k < mazes[i].w; k++){
							mazes[i].blk[j][k] = 0;
						}
					}
					maze_in_use[i] = 0;
					maze_pid[i] = 0;
					mazes[i].w = 0;
					mazes[i].h = 0;
					mazes[i].sx = 0;
					mazes[i].sy = 0;
					mazes[i].ex = 0;
					mazes[i].ey = 0;
					mazes[i].curx = 0;
					mazes[i].cury = 0;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_GETSIZE:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					coord_t coord_size = {mazes[i].w, mazes[i].h};
					if(copy_to_user((coord_t *)arg, &coord_size, sizeof(coord_t)))
						return -EBUSY;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_MOVE:
			can_find = 0;

			if(copy_from_user(&coord, (coord_t *)arg, sizeof(coord_t)))
				return -EBUSY;
			
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					if(mazes[i].blk[mazes[i].cury + coord.y][mazes[i].curx + coord.x] == 0) {
						mazes[i].curx += coord.x;
						mazes[i].cury += coord.y;
					}
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_GETPOS:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					coord_t coord_pos = {mazes[i].curx, mazes[i].cury};
					if(copy_to_user((coord_t *)arg, &coord_pos, sizeof(coord_t)))
						return -EBUSY;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_GETSTART:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					coord_t coord_start = {mazes[i].sx, mazes[i].sy};
					if(copy_to_user((coord_t *)arg, &coord_start, sizeof(coord_t)))
						return -EBUSY;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		case MAZE_GETEND:
			can_find = 0;
			for(int i = 0; i < _MAZE_MAXUSER; i++) {
				if(maze_pid[i] == current->pid) {
					can_find = 1;
					coord_t coord_end = {mazes[i].ex, mazes[i].ey};
					if(copy_to_user((coord_t *)arg, &coord_end, sizeof(coord_t)))
						return -EBUSY;
					break;
				}
			}

			if(can_find == 0)
				return -ENOENT;
			break;

		default:
			break;
	}
	return 0;
}

static const struct file_operations maze_dev_fops = {
	.owner = THIS_MODULE,
	.open = maze_dev_open,
	.read = maze_dev_read,
	.write = maze_dev_write,
	.unlocked_ioctl = maze_dev_ioctl,
	.release = maze_dev_close
};

static int maze_proc_read(struct seq_file *m, void *v) {
	// TODO: print all your maze if no maze print "vacany"
	for(int i = 0; i < _MAZE_MAXUSER; i++) {
		seq_printf(m, "#0%d: ", i);
		if(maze_in_use[i] == 1) {
			seq_printf(m, "pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n", maze_pid[i], mazes[i].w, mazes[i].h, mazes[i].sx, mazes[i].sy, mazes[i].ex, mazes[i].ey, mazes[i].curx, mazes[i].cury);
			for(int j = 0; j < mazes[i].h; j++) {
				seq_printf(m, "- %03d: ", j);
				for(int k = 0; k < mazes[i].w; k++) {
					if(mazes[i].curx == k && mazes[i].cury == j)
						seq_printf(m, "*");
					else if(mazes[i].sx == k && mazes[i].sy == j)
						seq_printf(m, "S");
					else if(mazes[i].ex == k && mazes[i].ey == j)
						seq_printf(m, "E");
					else if(mazes[i].blk[j][k] == 1)
						seq_printf(m, "#");
					else if(mazes[i].blk[j][k] == 0)
						seq_printf(m, ".");
				}
				seq_printf(m, "\n");
			}
		}
		else {
			seq_printf(m, "vacancy\n");
		}
		seq_printf(m, "\n");
	}
	return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
	.proc_open = maze_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init maze_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = maze_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&c_dev, &maze_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &maze_proc_fops);

	printk(KERN_INFO "maze: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit maze_cleanup(void)
{
	remove_proc_entry("maze", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
