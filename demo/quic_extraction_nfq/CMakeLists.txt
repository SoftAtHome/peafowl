add_executable(quic_extract quic_extraction_nfq.c)
target_link_libraries(quic_extract LINK_PUBLIC peafowl nfnetlink netfilter_queue)

if (ENABLE_DEMO)
    install(TARGETS quic_extract RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
