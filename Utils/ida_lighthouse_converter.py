import argparse

def real_all_addresses(trace_folder, pt_range, virtual_base):
    pt_ranges = pt_range.split('-')
    start = int(pt_ranges[0], 16)
    end = int(pt_ranges[1], 16)

    before = []
    with open(f'{trace_folder}/edges_uniq.lst', 'r') as f:
        for line in f.readlines():
            before.append(line[:-1])
    
    edges = []
    for b in before:
        addresses = b.split(',')
        for addr in addresses:
            if (start <= int(f'0x{addr}', 16) <= end):
                real_addr = int(f'0x{addr}', 16) - start + int(virtual_base, 16)
                if real_addr not in edges:
                    edges.append(hex(real_addr))

    return edges


def get_args():
    parser = argparse.ArgumentParser(description='kAFL v0.7 Lighthouse-converter')
    parser.add_argument('-t', help='trace folder')
    parser.add_argument('-ip', help='Intel-PT range (0xffffffff12341234-0xffffffff45674567)')
    parser.add_argument('-vb', help='virtual driver base (0x14000000)')
    parser.add_argument('-o', help='output file name')
    return parser.parse_args()

def write_file(trace_result):
    with open(output_name, 'a') as f:
        for r in trace_result:
            f.write(f'{r}\n')

def main():
    args = get_args()
    trace_folder, pt_range, virtual_base, output_name = args.t, args.ip, args.vb, args.o
    trace_result = real_all_addresses(trace_folder, pt_range, virtual_base)
    write_file(trace_result, output_name)

if __name__ == '__main__':
    main()

