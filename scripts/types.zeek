module Mercury;

type mercury_tcp_option: record {
	kind: count;
	data: string;
};

type mercury_tcp_option_list: vector of mercury_tcp_option;
