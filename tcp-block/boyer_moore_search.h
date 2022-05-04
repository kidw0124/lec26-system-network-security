/*
 * boyer_moore_search.h
 *
 *  Created on: 2017. 7. 24.
 *      Author: cobus
 */
#include <net/if.h>

#ifndef BOYER_MOORE_SEARCH_H_
#define BOYER_MOORE_SEARCH_H_

/**
 * 본문에서 찾고자 하는 패턴을 찾아서 위치를 반환한다.
 *
 * @param text
 * 		본문
 * @param text_size
 * 		본문의 길이
 * @param start
 * 		본문에서 탐색을 시작할 위치
 * @param pattern
 * 		본문에서 찾을 패턴
 * @param pattern_size
 * 		패턴의 길이
 * @return
 * 		-1: 패턴 찾지 못함
 * 		0이상: 본문에서 찾은 패턴의 index
 */
int boyer_moore_search(char *text, int text_size, int start, char *pattern,
		int pattern_size);
int boyer_moore_search(const u_char *text, int text_size, int start, char *pattern,
        int pattern_size);

#endif /* BOYER_MOORE_SEARCH_H_ */