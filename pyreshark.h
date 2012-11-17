#ifndef __PYRESHARK_H__
#define __PYRESHARK_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/packet.h>

#define PYTHON_DIR "python"
#define PYRESHARK_INIT_FILE "pyreshark.py"

typedef tvbuff_t * (*dissect_func_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int * p_offset, void * params);

typedef struct dissection_node_s {
    dissect_func_t func;
    void * params;
} dissection_node_t;

typedef struct py_dissector_s {
    dissection_node_t ** dissection_chain;
    int length;
    char * name;
} py_dissector_t;

void init_pyreshark();
void handoff_pyreshark();
void dissect_pyreshark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_proto(py_dissector_t * dissector_array, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void register_dissectors_array(int num_dissectors, py_dissector_t ** dissector_array);



#ifdef __cplusplus
}
#endif

#endif 