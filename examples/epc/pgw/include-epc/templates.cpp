templates.cpp

1- Get guti from packet.msui


	guti = 0;
	mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
	if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
		guti = s1mme_id[mme_s1ap_ue_id];
	}
