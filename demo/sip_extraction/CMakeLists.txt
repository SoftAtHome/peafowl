add_executable(sip_extraction sip_extraction.c)
target_link_libraries(sip_extraction LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS sip_extraction RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
