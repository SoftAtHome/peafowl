add_executable(rtp_extraction rtp_extraction.c)
target_link_libraries(rtp_extraction LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS rtp_extraction RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
