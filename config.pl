reject_adapter(Aid) :- split_string("A-C","-","",[Head1,Head2|Tail]),char_code(Head1,S1),char_code(Head2,S2),
		( (atom_chars(Aid,[H|T]),char_code(H,S3), between(S1,S2,S3));
		(split_string(Aid,",","",[Head3,Head4|Tail1]),char_code(Head3,S4),char_code(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).	


reject_ether_val(2).
reject_ether_val(3).
reject_ether_val(4).
reject_ether_val(5).

reject_proto_name("arp").
reject_proto_name("aarp").
reject_proto_name("atalk").


reject_proto_val(0x0800).

reject_src(Src) :- split_string("192.10.17.0-192.10.17.255","-","",[Head,Head2|Tail]),split_string(Head,".","",[X,Y,W,Z|Tail1]),
	atom_number(X,S1),atom_number(Y,S2),atom_number(W,S3),atom_number(Z,S4),split_string(Head2,".","",[B,C,D,E|Tail2]),
	atom_number(B,S5),atom_number(C,S6),atom_number(D,S7),atom_number(E,S8),split_string(Src,".","",[A1,A2,A3,A4|Tail3]),
	atom_number(A1,S9),atom_number(A2,S10),atom_number(A3,S11),atom_number(A4,S12),
	between(S1,S5,S9),between(S2,S6,S10),between(S3,S7,S11),between(S4,S8,S12).


reject_dest(Dest) :- split_string("192.10.17.0-192.10.17.255","-","",[Head,Head2|Tail]),split_string(Head,".","",[X,Y,W,Z|Tail1]),
	atom_number(X,S1),atom_number(Y,S2),atom_number(W,S3),atom_number(Z,S4),split_string(Head2,".","",[B,C,D,E|Tail2]),
	atom_number(B,S5),atom_number(C,S6),atom_number(D,S7),atom_number(E,S8),split_string(Dest,".","",[A1,A2,A3,A4|Tail3]),
	atom_number(A1,S9),atom_number(A2,S10),atom_number(A3,S11),atom_number(A4,S12),
	between(S1,S5,S9),between(S2,S6,S10),between(S3,S7,S11),between(S4,S8,S12).

reject_icmp_type("arp").
reject_icmp_type("mpls").

reject_icmp_val("Hi").

reject_tcp_src(Port):- split_string("20-80","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).		.

reject_tcp_dest(Port):- split_string("20-80","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).	

reject_udp_src(Port):- split_string("20-80","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).

reject_udp_dest(Port):- split_string("20-80","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).








drop_adapter(Aid) :- split_string("D-F","-","",[Head1,Head2|Tail]),char_code(Head1,S1),char_code(Head2,S2),
		( (atom_chars(Aid,[H|T]),char_code(H,S3), between(S1,S2,S3));
		(split_string(Aid,",","",[Head3,Head4|Tail1]),char_code(Head3,S4),char_code(Head4,S5), between(S1,S2,S4),between(S1,S2,S5));
		(Aid="null") ).	


drop_ether_val(1).


drop_proto_name("ipx").
drop_proto_name("mpls").

drop_proto_val(0x08dd).

drop_src(Src) :- split_string("192.10.16.0-192.10.16.255","-","",[Head,Head2|Tail]),split_string(Head,".","",[X,Y,W,Z|Tail1]),
	atom_number(X,S1),atom_number(Y,S2),atom_number(W,S3),atom_number(Z,S4),split_string(Head2,".","",[B,C,D,E|Tail2]),
	atom_number(B,S5),atom_number(C,S6),atom_number(D,S7),atom_number(E,S8),split_string(Src,".","",[A1,A2,A3,A4|Tail3]),
	atom_number(A1,S9),atom_number(A2,S10),atom_number(A3,S11),atom_number(A4,S12),
	between(S1,S5,S9),between(S2,S6,S10),between(S3,S7,S11),between(S4,S8,S12).


drop_dest(Dest) :- split_string("192.10.16.0-192.10.16.255","-","",[Head,Head2|Tail]),split_string(Head,".","",[X,Y,W,Z|Tail1]),
	atom_number(X,S1),atom_number(Y,S2),atom_number(W,S3),atom_number(Z,S4),split_string(Head2,".","",[B,C,D,E|Tail2]),
	atom_number(B,S5),atom_number(C,S6),atom_number(D,S7),atom_number(E,S8),split_string(Dest,".","",[A1,A2,A3,A4|Tail3]),
	atom_number(A1,S9),atom_number(A2,S10),atom_number(A3,S11),atom_number(A4,S12),
	between(S1,S5,S9),between(S2,S6,S10),between(S3,S7,S11),between(S4,S8,S12).

drop_icmp_type("aarp").
drop_icmp_type("ipx").

drop_icmp_val("Hello").

drop_tcp_src(Port):- split_string("1000-7000","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).		.

drop_tcp_dest(Port):- split_string("1000-7000","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).	

drop_udp_src(Port):- split_string("1000-7000","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).

drop_udp_dest(Port):- split_string("1000-7000","-","",[Head1,Head2|Tail]),atom_number(Head1,S1),atom_number(Head2,S2),
		(( atom_number(Port,S3), between(S1,S2,S3)); 
		(split_string(Port,",","",[Head3,Head4|Tail1]),atom_number(Head3,S4),atom_number(Head4,S5), between(S1,S2,S4),between(S1,S2,S5))).



firewall([A,B,C,D,E,F,G,H,I,J,K,L]) :- write("Waiting"),nl,
	((drop_adapter(A);
	drop_ether_val(B);
	drop_proto_name(C);
	drop_proto_val(D);
	drop_src(E);
	drop_dest(F);
	drop_icmp_type(G);
	drop_icmp_val(H);
	drop_tcp_src(I);
	drop_tcp_dest(J);
	drop_udp_src(K);
	drop_udp_dest(L)),
	write("Dropped"));

	((reject_adapter(A);
	reject_ether_val(B);
	reject_proto_name(C);
	reject_proto_val(D);
	reject_src(E);
	reject_dest(F);
	reject_icmp_type(G);
	reject_icmp_val(H);
	reject_tcp_src(I);
	reject_tcp_dest(J);
	reject_udp_src(K);
	reject_udp_dest(L)),
	write("Rejected"));
	
	write("Accepted").

?firewall(['A',2,"arp",0x0800,"192.10.17.1","192.10.17.10","arp","Hi",20,20,20,20]).
Waiting
Accepted