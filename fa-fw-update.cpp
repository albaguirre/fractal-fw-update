/*
 * Copyright (c) 2018 Alberto Aguirre
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <alsa/asoundlib.h>

namespace
{
std::atomic<bool> running{true};
void sig_handler(int signal)
{
    running = false;
}

void usage(const std::string& name)
{
    std::cerr << name << " <sysex file> <port_name>\n";
}

constexpr int MIN_SYSEX_SIZE{8};
constexpr uint8_t SYSEX_START{0xF0};
constexpr uint8_t SYSEX_END{0xF7};
constexpr std::array<uint8_t, 3> FRACTAL_AUDIO_MANUFACTURER_ID{0x00, 0x01, 0x74};
const std::unordered_map<uint8_t, std::string> model_ids = {
    {0x00, "Axe-Fx Standard"}, {0x01, "Axe-Fx Ultra"},  {0x02, "MFC-101"},
    {0x03, "Axe-Fx II"},       {0x04, "MFC-101 mk3"},   {0x05, "FX8"},
    {0x06, "Axe-Fx II XL"},    {0x07, "Axe-Fx II XL+"}, {0x08, "AX8"},
    {0x0A, "FX8 mk2"},         {0x10, "Axe-Fx III"}};

constexpr uint8_t FIRMWARE_UPDATE_START{0x7D};
constexpr uint8_t FIRMWARE_UPDATE_DATA{0x7E};
constexpr uint8_t FIRMWARE_UPDATE_END{0x7F};
constexpr uint8_t MULTI_PURPOSE_RESPONSE{0x64};
const std::unordered_map<uint8_t, std::string> commands = {
    {FIRMWARE_UPDATE_START, "firmware update start"},
    {FIRMWARE_UPDATE_DATA, "firmware update data"},
    {FIRMWARE_UPDATE_END, "firmware update end"},
    {MULTI_PURPOSE_RESPONSE, "multi purpose response"}};

class SysexMessage
{
public:
    SysexMessage(uint8_t* data, std::size_t size) : data{data}, size{size}
    {
        if (size < MIN_SYSEX_SIZE)
            throw std::invalid_argument("Sysex message is to small for Fractal Audio products");

        if (data[0] != SYSEX_START || data[size - 1] != SYSEX_END)
            throw std::invalid_argument("Not a valid sysex message");

        verify_id();
        verify_model();
        verify_checksum();
    }

    auto the_data() const { return data; }
    auto the_size() const { return size; }

    auto model() const
    {
        const auto model = data[4];
        return model_ids.find(model)->second;
    }

    auto checksum() const { return data[size - 2]; }
    auto command() const { return data[5]; }
    auto response_id() const { return data[6]; }

    bool is_response_to(const SysexMessage& sent_msg)
    {
        return command() == MULTI_PURPOSE_RESPONSE && response_id() == sent_msg.command();
    }

    std::string command_name() const
    {
        auto entry = commands.find(command());
        if (entry == commands.end())
            return "unknown";
        return entry->second;
    }

    void print(std::ostream& os) const
    {
        os << "["
           << "size: " << size << ", model: " << model() << ", command: " << command_name() << "]";
    }

    void print_raw(std::ostream& os) const
    {
        std::stringstream hex_stream;
        for (size_t i = 0; i < size; ++i)
            hex_stream << std::hex << static_cast<int>(data[i]) << " ";
        os << hex_stream.str();
    }

private:
    void verify_id()
    {
        std::array<uint8_t, 3> msg_id{data[1], data[2], data[3]};
        if (msg_id != FRACTAL_AUDIO_MANUFACTURER_ID)
            throw std::invalid_argument("Not a Fractal Audio Sysex message");
    }

    void verify_model()
    {
        const auto model = data[4];
        auto entry = model_ids.find(model);
        if (entry == model_ids.end())
            throw std::invalid_argument(
                "This sysex message is for an unrecognized Fractal Audio product");
    }

    void verify_checksum()
    {
        uint8_t checksum = 0;
        for (size_t i = 0; i < size - 2; ++i)
            checksum ^= data[i];
        checksum &= 0x7F;

        const auto msg_checksum = data[size - 2];
        if (checksum != msg_checksum)
            throw std::invalid_argument("Invalid message checksum");
    }

    uint8_t* data;
    std::size_t size;
};

std::ostream& operator<<(std::ostream& os, const SysexMessage& msg)
{
    msg.print(os);
    return os;
}

class File
{
public:
    File(const std::string& name) : fp{std::fopen(name.c_str(), "r"), std::fclose}
    {
        if (fp == nullptr)
            throw std::runtime_error("failed to open file " + name);

        std::fseek(fp.get(), 0, SEEK_END);
        size = static_cast<std::size_t>(std::ftell(fp.get()));
        std::fseek(fp.get(), 0, SEEK_SET);
    }

    std::vector<uint8_t> read_all() const
    {
        std::vector<uint8_t> buffer(size);
        auto ret = std::fread(buffer.data(), 1, buffer.size(), fp.get());
        if (ret < buffer.size())
            throw std::runtime_error("failed to read all contents");
        return buffer;
    }

private:
    std::unique_ptr<FILE, decltype(std::fclose)*> fp;
    std::size_t size;
};

class SysexFile
{
public:
    SysexFile(const File& file) : data{file.read_all()}
    {
        auto it = data.begin();
        while (it != data.end())
        {
            const auto msg_data = &*it;
            auto it_to_next_message = std::find(it + 1, data.end(), SYSEX_START);
            size_t size = std::distance(it, it_to_next_message);
            messages.emplace_back(msg_data, size);

            it = it_to_next_message;
        }
    }

    auto begin() { return messages.begin(); }
    auto end() { return messages.end(); }
    auto file_size() const { return data.size(); }

private:
    std::vector<uint8_t> data;
    std::vector<SysexMessage> messages;
};

struct SndRawMidiDeleter
{
    void operator()(snd_rawmidi_t* t) { snd_rawmidi_close(t); }
};

class RawMidiIO
{
public:
    RawMidiIO(const std::string& port_name) : input{nullptr}, output{nullptr}
    {
        snd_rawmidi_t* in{nullptr};
        snd_rawmidi_t* out{nullptr};
        auto ret = snd_rawmidi_open(&in, &out, port_name.c_str(), SND_RAWMIDI_NONBLOCK);
        if (ret < 0)
            throw std::runtime_error("cannot open port " + port_name +
                                     " due to: " + std::string(snd_strerror(ret)));

        input = std::move(SndRawMidiUPtr(in));
        output = std::move(SndRawMidiUPtr(out));
        if (input == nullptr)
            throw std::runtime_error("failed to open input port");
        if (output == nullptr)
            throw std::runtime_error("failed to open output port");

        ret = snd_rawmidi_nonblock(output.get(), 0);
        if (ret < 0)
            throw std::runtime_error("cannot set blocking mode for output: " +
                                     std::string(snd_strerror(ret)));

        snd_rawmidi_read(input.get(), nullptr, 0);
        snd_rawmidi_status_alloca(&st);
    }

    void wait_for_ack_for(const SysexMessage& sent_msg)
    {
        std::vector<uint8_t> buffer(10);

        int size_needed = buffer.size();
        auto p = buffer.data();

        while (size_needed > 0)
        {
            auto bytes_read = snd_rawmidi_read(input.get(), p, size_needed);
            if (bytes_read == -EAGAIN)
                continue;
            if (bytes_read < 0)
                throw std::runtime_error("failed to read midi input");

            size_needed -= bytes_read;
            p += bytes_read;
        }

        SysexMessage ack{buffer.data(), buffer.size()};
        std::cerr << "  reply   " << ack << "\n";

        if (!ack.is_response_to(sent_msg))
            throw std::runtime_error("unexpected device response");
    }

    void send_sysex(const SysexMessage& msg)
    {
        std::cerr << "  sending " << msg << "\n";
        auto written = snd_rawmidi_write(output.get(), msg.the_data(), msg.the_size());
        if (written < 0)
            throw std::runtime_error("failed to write data: " + std::string(snd_strerror(written)));

        if (static_cast<size_t>(written) < msg.the_size())
            throw std::runtime_error("couldn't write the full message");

        wait_for_ack_for(msg);
    }

private:
    using SndRawMidiUPtr = std::unique_ptr<snd_rawmidi_t, SndRawMidiDeleter>;
    SndRawMidiUPtr input;
    SndRawMidiUPtr output;
    snd_rawmidi_status_t* st;
};

template <typename S>
void print_progress(const S& start, std::size_t bytes_sent, double total_size)
{
    using sec = std::chrono::duration<double>;
    auto delta_time = std::chrono::steady_clock::now() - start;
    auto kb = bytes_sent / 1024.0;
    auto progress_percent = 100.0 * (bytes_sent / total_size);
    std::cerr << "  progress: " << progress_percent << "%"
              << ", speed: " << kb / std::chrono::duration_cast<sec>(delta_time).count() << " KB/s"
              << ", time elapsed: "
              << std::chrono::duration_cast<std::chrono::seconds>(delta_time).count()
              << " seconds\n";
}

template <typename S>
void print_total(const S& start)
{
    using min = std::chrono::duration<double, std::ratio<60>>;
    auto delta_time = std::chrono::steady_clock::now() - start;
    std::cerr << "firmware update took: " << std::chrono::duration_cast<min>(delta_time).count()
              << " minutes\n";
}
}  // namespace

int main(int argc, char* argv[]) try
{
    if (argc != 3)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, sig_handler);

    RawMidiIO midi{argv[2]};
    File file{argv[1]};
    SysexFile sysex_file{file};

    int count{0};
    std::size_t bytes_sent{0};
    const auto total_size = sysex_file.file_size();
    auto start = std::chrono::steady_clock::now();

    for (auto& msg : sysex_file)
    {
        if (!running)
            break;

        std::cerr << "message " << ++count << "\n";
        midi.send_sysex(msg);

        bytes_sent += msg.the_size();
        print_progress(start, bytes_sent, total_size);
    }

    if (running)
    {
        print_total(start);
        std::cerr << "Done. Goodbye!\n";
    }
    else
    {
        std::cerr << "Why would you interrupt a firmware update? Fine, Goodbye!\n";
    }
}
catch (const std::exception& e)
{
    std::cerr << "error: " << e.what() << "\n";
    return EXIT_FAILURE;
}
