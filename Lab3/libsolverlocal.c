#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "libmaze.h"

static void * __stored_ptr = NULL;
int visited[_MAZE_MAXY][_MAZE_MAXX] = {0};
int path[100000] = {-1};
int top = -1;
int end = 0;

static int _dirx[] = { 0, 0, -1, 1 };
static int _diry[] = { -1, 1, 0, 0 };

void dfs(maze_t *mz, int visited[_MAZE_MAXY][_MAZE_MAXX]) {
    visited[mz->cy][mz->cx] = 1;
	if(mz->cx == mz->ex && mz->cy == mz->ey) {
		end = 1;
		return;
	}
    for (int i = 0; i < 4; i++) {
        int nx = mz->cx + _dirx[i];
        int ny = mz->cy + _diry[i];
		
        if (ny < 0 || ny >= mz->h || nx < 0 || nx >= mz->w) 
            //Out of bound
			continue;
        if (mz->blk[ny][nx] != 0 || visited[ny][nx] != 0) 
            //Wall or visited
			continue;
        
		mz->cx = nx;
		mz->cy = ny;

        if (i == 0) {
			//move up
			top++;
			path[top] = 0;
            dfs(mz, visited);
			if(end == 1) break;
			path[top] = -1;
			top--;
        }
        if (i == 1) {
			//move down
			top++;
			path[top] = 1;
			dfs(mz, visited);
			if(end == 1) break;
			path[top] = -1;
			top--;
		}
		if (i == 2) {
			//move left
			top++;
			path[top] = 2;
			dfs(mz, visited);
			if(end == 1) break;
			path[top] = -1;
			top--;
		}
		if (i == 3) {
			//move right
			top++;
			path[top] = 3;
			dfs(mz, visited);
			if(end == 1) break;
			path[top] = -1;
			top--;
		}
		mz->cx -= _dirx[i];
        mz->cy -= _diry[i];
    }
}

int
maze_init() {
	fprintf(stderr, "MAZE: library init - stored pointer = %p.\n", __stored_ptr);
	
	maze_t *mz = NULL;
	if((mz = maze_load("./maze.txt")) == NULL) {
		fprintf(stderr, "Maze load failed.\n");
		return -1;
	}
	
	dfs(mz, visited);

	for(int i = 0; i <= top; i++) {
		if(path[i] == 0) move_up(mz);
		if(path[i] == 1) move_down(mz);
		if(path[i] == 2) move_left(mz);
		if(path[i] == 3) move_right(mz);
	}

	return 0;
}