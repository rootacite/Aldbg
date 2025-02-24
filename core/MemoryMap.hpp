
#include <string>

#ifndef _H_MEMORYMAP
#define _H_MEMORYMAP 1

static std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(str);

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

enum Access{
    READ    = 0x01,
    WRITE   = 0x02,
    EXECUTE = 0x04,
    PRIVATE = 0x08,
    SHARED  = 0x10
};

struct MapEntire
{
    uint64_t startAddress;
    uint64_t endAddress;
    uint8_t  access = 0;
    uint32_t offset;
    char path[512] = {0};

    MapEntire()
    {
        startAddress = 0;
        endAddress = 0;
        offset = 0;
    }

    explicit MapEntire(const std::string& src)
    {
        auto e = split(src, ' ');
        for(int i=0;i<e.size();i++)
            if(e[i].empty())
            {
                e.erase(e.begin() + i);
                i--;
                continue;
            }

        startAddress = std::stoull(split(e[0], '-')[0], nullptr, 16);
        endAddress = std::stoull(split(e[0], '-')[1], nullptr, 16);

        if(e[1].contains("r")) access |= READ;
        if(e[1].contains("w")) access |= WRITE;
        if(e[1].contains("x")) access |= EXECUTE;
        if(e[1].contains("p")) access |= PRIVATE;
        if(e[1].contains("s")) access |= SHARED;

        offset = std::stoull(e[2], nullptr, 16);

        if(e.size() < 6) return;
        e[5].erase(e[5].end() - 1);
        strcpy(path, e[5].c_str());
    }
};

class MemoryMap
{
protected:
    static bool readAll(std::vector<std::string>& dst, const std::string& path)
    {
        auto f = fopen(path.c_str(), "r");
        if(!f){ perror("fopen()"); return false; }

        dst.clear();
        char line[1024];
        while(fgets(line, 1024, f))
        {
            dst.emplace_back(line);
        }
        fclose(f);

        return true;
    }

private:
    char _path[255] = {0};
    std::vector<std::string> _content;

public:
    explicit MemoryMap(int pid)
    {
        sprintf(_path, "/proc/%d/maps", pid);
        readAll(_content, _path);
    }

    MapEntire GetItem(int index)
    {
        auto u = MapEntire(_content[index]);
        return u;
    }

    size_t Size()
    {
        return _content.size();
    }

    std::vector<MapEntire> GetModules()
    {
        std::vector<MapEntire> r;
        for(int i=0;i<Size();i++)
        {
            auto k = GetItem(i);
            if(!std::ranges::any_of(r, [&](const MapEntire& i){
                return strcmp(k.path, i.path) == 0;
            }) && k.path[0] && k.path[0] != '[' )
            {
                r.emplace_back(k);
            }
            if(strcmp(k.path, (*(r.end() - 1)).path) == 0)
            {
                (*(r.end() - 1)).endAddress = k.endAddress;
            }
        }

        return r;
    }
};

#endif