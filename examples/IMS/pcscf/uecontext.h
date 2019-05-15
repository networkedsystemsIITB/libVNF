#include <functional>

#include <boost/serialization/access.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <string> 
#include <sstream>
//using namespace std;
class UEcontext
{
public:
	int sipheader;
	int emm_state; /* EPS Mobililty Management state */
	/* UE id */
	uint64_t imsi; /* International Mobile Subscriber Identity.  */
	int privateidentity; 
	uint64_t instanceid;
	uint64_t gruu; /* GRUU */
	/* Network Operator info */
	uint64_t expiration_value ; // 0 in case of deregistration, otherwise non zero
	/* UE security context */
	uint64_t key; /* Primary key used in generating secondary keys */
	uint64_t k_asme; /* Key for Access Security Management Entity */
	uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
	uint64_t count;
	uint64_t integrity_protected;

	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t res;
	uint64_t ck;
	uint64_t ik;
	uint64_t expiration_time;
	uint64_t registered;
	//std::string scscf_addr; // Stores IP Address of SCSCF
	char* scscf_addr; // Stores IP Address of SCSCF
	uint64_t scscf_port; // SCSCF Port
	UEcontext();
        ~UEcontext();
	template<class Archive>
	void serialize(Archive &ar, const unsigned int version);
};
template<typename T>
        std::string toBoostString(T const &obj){
                std::stringstream ofs;
                boost::archive::text_oarchive oa(ofs);
                oa << obj;
                return ofs.str();
        }


        template<typename T>
        T const & toBoostObject(std::string sobj){
                T *obj = new(T);
                std::stringstream ifs;
                ifs << sobj;
                boost::archive::text_iarchive ia(ifs);
                ia >> (*obj);
                return *obj;
        }

