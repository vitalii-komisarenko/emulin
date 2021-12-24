require_relative "addressable"

class Memory < Addressable
    def initialize
        super
        @name = "memory"
    end

    def type
        "mem"
    end
end
