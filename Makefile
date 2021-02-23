all clean:
	$(MAKE) -C fanotify $@
	$(MAKE) -C audit $@
	$(MAKE) -C ptrace $@
.PHONY: all clean
