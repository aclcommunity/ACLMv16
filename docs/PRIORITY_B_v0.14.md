# Priority B — systems control (v0.14.0)

## Added
| API | Meaning |
|-----|---------|
| `cell:mapfile dest = size, fd [, offset [, prot]]` | file-backed mmap (MAP_PRIVATE) |
| `thread:join_all` | wait until done_count >= spawn_count |
| spawn_count in thr futex [+16] | tracks spawned workers |
| `net:poll fds, nfds, timeout_ms` | poll(2) |
| `net:epoll_create dest = flags` | epoll_create1 |
| `net:epoll_ctl epfd, op, fd, event_ptr` | epoll_ctl |
| `net:epoll_wait dest = epfd, events, max, timeout` | epoll_wait |

## Tests
- test_310_mapfile (/dev/zero)
- test_311_join_all
- test_312_poll_timeout
- test_313_epoll_create

## Notes
- join_all is completion-counter based (not waitid per tid)
- sig:action remains thin (SIG_IGN path verified earlier)
