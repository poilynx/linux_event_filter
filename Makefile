all clean:
	$(MAKE) -C fanotify $@
	$(MAKE) -C audit $@
	$(MAKE) -C ptrace $@
	$(MAKE) -C connector $@
.PHONY: all clean
