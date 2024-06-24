add_executable(ssl_extraction ssl_extraction.c)
target_link_libraries(ssl_extraction LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS ssl_extraction RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
