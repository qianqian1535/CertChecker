/* * * * * * *
 * Module for creating and manipulating singly-linked lists containing data
 * of any type
 *
 * based on COMP20007 Design of Algorithms - Assignment 1, 2018
 * by Matt Farrugia <matt.farrugia@unimelb.edu.au>
 */

#include <stdlib.h>
#include <assert.h>
#include "list.h"

/*                         DO NOT CHANGE THIS FILE
 *
 * DO NOT add or modify any definitions or anything else inside this file.
 *
 * We will test your assignment with an unmodified version of this file. Any
 * changes you make will be lost. This may lead to compile errors.
 */


// helper function to create a new node and return its address
Node *new_node();

// helper function to clear memory of a node (does not free the node's data)
void free_node(Node *node);

/* * * *
 * FUNCTION DEFINITIONS
 */

// create a new, empty list and return its pointer
List *new_list() {
	List *list = malloc(sizeof *list);
	assert(list);

	list->head = NULL;
	list->last = NULL;
	list->size = 0;

	return list;
}

// destroy a list and free its memory
// DOES NOT FREE POINTERS TO DATA HELD IN THE LISTS NODES, only frees the nodes
void free_list(List *list) {
	assert(list != NULL);
	// free each node
	Node *node = list->head;
	Node *next;
	while (node) {
		next = node->next;
		free_node(node);
		node = next;
	}
	// free the list struct itself
	free(list);
}

void free_word_list(List *list) {
	// free the words in the list (they were malloced by this module)
	Node *node = list->head;
	while (node) {
		free(node->name);
		node->name = NULL;
		free(node->url);
		node->url = NULL;
		node = node->next;
	}

	free_list(list);
}

// helper function to create a new node and return its address
// DOES NOT INITIALISE THE NODE'S DATA
Node *new_node() {
	Node *node = malloc(sizeof *node);
	assert(node);

	return node;
}

// helper function to clear memory of a node
// DOES NOT FREE THE NEXT NODE OR THE NODE'S DATA
void free_node(Node *node) {
	free(node);
}

// add an element to the back of a list
// this operation is O(1)
void list_add_end(List* list, char *name, char *url){
	assert(list != NULL);

	// we'll need a new list node to store this data
	Node *node = new_node();
	node->name = name;
	node->url = url;
	node-> valid = false; //set default validity to false
	node->next = NULL; // as the last node, there's no next node

	if(list->size == 0) {
		// if the list was empty, new node is now the first node
		list->head = node;
	} else {
		// otherwise, it goes after the current last node
		list->last->next = node;
	}

	// place this new node at the end of the list
	list->last = node;

	// and keep size updated too
	list->size++;
}

// return the number of elements contained in a list
int list_size(List *list) {
	assert(list != NULL);

	return list->size;
}

// returns whether the list contains no elements (true) or some elements (false)
bool list_is_empty(List *list) {
	assert(list != NULL);

	return (list->size==0);
}
