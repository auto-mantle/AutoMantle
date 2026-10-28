package com.automantle.api.controller;
import com.automantle.api.service.VmGatewayService;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VmControllerTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path files;
    @Test void browsesLocalIsoPathsWithoutUploadingContents() throws Exception {
        var gateway = mock(VmGatewayService.class);
        var controller = new VmController(gateway);
        java.nio.file.Files.createDirectory(files.resolve("downloads"));
        java.nio.file.Files.writeString(files.resolve("ubuntu.iso"), "iso");
        java.nio.file.Files.writeString(files.resolve("private.txt"), "hidden");
        var result = controller.browse(new VmController.Browse(files.toString()));
        var entries = (List<Map<String,Object>>) result.get("entries");
        assertEquals(List.of("downloads", "ubuntu.iso"), entries.stream().map(e -> e.get("name")).toList());
        assertEquals(files.resolve("ubuntu.iso").toRealPath().toString(), entries.get(1).get("path"));
        verifyNoInteractions(gateway);
    }
    private static final String RUN = "automantle-vm-" + "a".repeat(32);
    @Test void validatesTerminalBytesAndBindsWritesToOneRun() throws Exception {
        var gateway = mock(VmGatewayService.class);
        var controller = new VmController(gateway);
        for (List<Integer> bytes : List.of(List.<Integer>of(), List.of(-1), List.of(256), java.util.Collections.nCopies(4097, 1))) {
            assertThrows(IllegalArgumentException.class, () -> controller.input(RUN, new VmController.Input(bytes)));
        }
        assertThrows(IllegalArgumentException.class, () -> controller.input("../host", new VmController.Input(List.of(1))));
        assertThrows(IllegalArgumentException.class, () -> controller.output(RUN, -1));
        verifyNoInteractions(gateway);
        controller.input(RUN, new VmController.Input(List.of(27,195,169,13)));
        verify(gateway).command(Map.of("command","terminal-write","id",RUN,"data",List.of(27,195,169,13)));
    }
    @Test void validatesSavedSettingsBeforeContactingGateway() throws Exception {
        var gateway=mock(VmGatewayService.class);var controller=new VmController(gateway);var profile=UUID.randomUUID();
        assertThrows(IllegalArgumentException.class,()->controller.create(new VmController.Settings("VM",null,512,1,false,"/tmp/os.iso")));
        assertThrows(IllegalArgumentException.class,()->controller.create(new VmController.Settings("VM",profile,127,1,false,"/tmp/os.iso")));
        assertThrows(IllegalArgumentException.class,()->controller.create(new VmController.Settings("VM",profile,512,0,false,"/tmp/os.iso")));
        assertThrows(IllegalArgumentException.class,()->controller.create(new VmController.Settings("\n",profile,512,1,false,"/tmp/os.iso")));
        assertThrows(IllegalArgumentException.class,()->controller.create(new VmController.Settings("VM",profile,512,1,false,null)));
        assertThrows(IllegalArgumentException.class,()->controller.update("../host",new VmController.Settings("VM",profile,512,1,false,null)));
        verifyNoInteractions(gateway);
        controller.create(new VmController.Settings(" First ",profile,2048,2,true," /tmp/os.iso "));
        verify(gateway).command(Map.of("command","create-machine","settings",Map.of("name","First","agentProfileId",profile.toString(),"memoryMib",2048,"vcpuCount",2,"setup",true),"isoPath","/tmp/os.iso"));
    }
    @Test void machinePowerCopyAndDeleteUseStableIdentity() throws Exception {
        var gateway=mock(VmGatewayService.class);var controller=new VmController(gateway);
        controller.start("antigravity");controller.reinstall("antigravity");controller.completeInstallation("antigravity");controller.stop("antigravity");controller.forceStop("antigravity");
        controller.copy("antigravity",new VmController.CopyVm("Copy"));controller.delete("antigravity");
        verify(gateway).command(Map.of("command","start-machine","id","antigravity"));
        verify(gateway).command(Map.of("command","reinstall-machine","id","antigravity"));
        verify(gateway).command(Map.of("command","complete-installation","id","antigravity"));
        verify(gateway).command(Map.of("command","shutdown-machine","id","antigravity"));
        verify(gateway).command(Map.of("command","force-stop-machine","id","antigravity"));
        verify(gateway).command(Map.of("command","copy-machine","id","antigravity","name","Copy"));
        verify(gateway).command(Map.of("command","delete-machine","id","antigravity"));
    }
}
